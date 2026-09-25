//go:build linux

package fs

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"common.queueb.org/keyring/internal/contract"

	"golang.org/x/sys/unix"
)

const (
	mountInfoPath        = "/proc/self/mountinfo"
	maximumMountInfoLine = 1024 * 1024
)

type mountDevice struct {
	major uint32
	minor uint32
}

type mount struct {
	device       mountDevice
	point        string
	filesystem   string
	source       string
	superOptions string
}

type mountEnvironment interface {
	absolute(string) (string, error)
	stat(string, *unix.Stat_t) error
	evaluateSymlinks(string) (string, error)
	openMountInfo() (io.ReadCloser, error)
}

type linuxMountEnvironment struct{}

func (linuxMountEnvironment) absolute(path string) (string, error) {
	return filepath.Abs(path)
}

func (linuxMountEnvironment) stat(path string, status *unix.Stat_t) error {
	return unix.Stat(path, status)
}

func (linuxMountEnvironment) evaluateSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

func (linuxMountEnvironment) openMountInfo() (io.ReadCloser, error) {
	return os.Open(mountInfoPath)
}

func validateMount(rootPath string) error {
	return validateMountWithEnvironment(rootPath, linuxMountEnvironment{})
}

func validateMountWithEnvironment(rootPath string, environment mountEnvironment) error {
	existingPath, device, err := nearestExistingPath(rootPath, environment)
	if err != nil {
		return err
	}

	mountInfo, err := environment.openMountInfo()
	if err != nil {
		return mountError("open mount metadata", err)
	}
	defer mountInfo.Close()

	mounts, err := parseMountInfo(mountInfo)
	if err != nil {
		return mountError("parse mount metadata", err)
	}
	selected, err := selectMount(mounts, existingPath, device)
	if err != nil {
		return mountError("identify fallback filesystem", err)
	}
	if selected.isDrvFS() {
		return fmt.Errorf(
			"%w: DrvFS mount %q is not permitted",
			contract.ErrInsecureFallback,
			selected.point,
		)
	}
	return nil
}

func nearestExistingPath(rootPath string, environment mountEnvironment) (string, mountDevice, error) {
	path, err := environment.absolute(rootPath)
	if err != nil {
		return "", mountDevice{}, mountError("resolve fallback path", err)
	}
	path = filepath.Clean(path)

	for {
		var status unix.Stat_t
		err := environment.stat(path, &status)
		if err == nil {
			path, err = environment.evaluateSymlinks(path)
			if err != nil {
				return "", mountDevice{}, mountError("resolve fallback symlinks", err)
			}
			device := uint64(status.Dev)
			return path, mountDevice{
				major: unix.Major(device),
				minor: unix.Minor(device),
			}, nil
		}
		if !errors.Is(err, iofs.ErrNotExist) {
			return "", mountDevice{}, mountError("inspect fallback path", err)
		}

		parent := filepath.Dir(path)
		if parent == path {
			return "", mountDevice{}, mountError(
				"locate existing fallback parent",
				err,
			)
		}
		path = parent
	}
}

func parseMountInfo(contents io.Reader) ([]mount, error) {
	scanner := bufio.NewScanner(contents)
	scanner.Buffer(nil, maximumMountInfoLine)
	var mounts []mount
	for scanner.Scan() {
		entry, err := parseMountInfoLine(scanner.Text())
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return mounts, nil
}

func parseMountInfoLine(line string) (mount, error) {
	fields := strings.Fields(line)
	separator := -1
	for index, field := range fields {
		if field == "-" {
			separator = index
			break
		}
	}
	if separator < 6 || len(fields) < separator+4 {
		return mount{}, fmt.Errorf("invalid mountinfo record")
	}

	device, err := parseMountDevice(fields[2])
	if err != nil {
		return mount{}, err
	}
	point, err := unescapeMountField(fields[4])
	if err != nil {
		return mount{}, err
	}
	source, err := unescapeMountField(fields[separator+2])
	if err != nil {
		return mount{}, err
	}
	return mount{
		device:       device,
		point:        filepath.Clean(point),
		filesystem:   fields[separator+1],
		source:       source,
		superOptions: fields[separator+3],
	}, nil
}

func parseMountDevice(value string) (mountDevice, error) {
	majorValue, minorValue, ok := strings.Cut(value, ":")
	if !ok {
		return mountDevice{}, fmt.Errorf("invalid mount device %q", value)
	}
	major, err := strconv.ParseUint(majorValue, 10, 32)
	if err != nil {
		return mountDevice{}, fmt.Errorf("invalid mount major %q: %w", majorValue, err)
	}
	minor, err := strconv.ParseUint(minorValue, 10, 32)
	if err != nil {
		return mountDevice{}, fmt.Errorf("invalid mount minor %q: %w", minorValue, err)
	}
	return mountDevice{major: uint32(major), minor: uint32(minor)}, nil
}

func unescapeMountField(value string) (string, error) {
	var result strings.Builder
	result.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			result.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", fmt.Errorf("truncated mountinfo escape in %q", value)
		}
		escape := value[index+1 : index+4]
		decoded, ok := map[string]byte{
			"011": '\t',
			"012": '\n',
			"040": ' ',
			"134": '\\',
		}[escape]
		if !ok {
			return "", fmt.Errorf("unsupported mountinfo escape \\%s", escape)
		}
		result.WriteByte(decoded)
		index += 3
	}
	return result.String(), nil
}

func selectMount(mounts []mount, path string, device mountDevice) (mount, error) {
	var selected mount
	found := false
	for _, candidate := range mounts {
		if candidate.device != device || !pathWithinMount(path, candidate.point) {
			continue
		}
		if !found || len(candidate.point) >= len(selected.point) {
			selected = candidate
			found = true
		}
	}
	if !found {
		return mount{}, fmt.Errorf("mount for device %d:%d and path %q was not found", device.major, device.minor, path)
	}
	return selected, nil
}

func pathWithinMount(path, mountPoint string) bool {
	relative, err := filepath.Rel(mountPoint, path)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (m mount) isDrvFS() bool {
	if strings.EqualFold(m.filesystem, "drvfs") || strings.EqualFold(m.source, "drvfs") {
		return true
	}
	if m.filesystem != "9p" {
		return false
	}
	for option := range strings.SplitSeq(m.superOptions, ",") {
		option = strings.ToLower(option)
		if option == "aname=drvfs" || strings.HasPrefix(option, "aname=drvfs;") {
			return true
		}
	}
	return false
}

func mountError(operation string, err error) error {
	return fmt.Errorf("%w: %s: %w", contract.ErrInsecureFallback, operation, err)
}
