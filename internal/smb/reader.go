package smb

import (
	"errors"
	"fmt"
	"io"
	"os"
)

func (c *Client) ReadFile(share, path string) ([]byte, error) {
	fs, err := c.mountShareWithDeadline(share)
	if err != nil {
		return nil, err
	}
	defer c.umountShareWithDeadline(fs)

	guard := c.beginOperation()
	info, err := fs.Stat(path)
	err = guard.finish(err)
	if err != nil {
		return nil, fmt.Errorf("stat %s on %s: %w", path, share, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s on %s is a directory", path, share)
	}
	if c.maxReadSize > 0 && info.Size() > c.maxReadSize {
		return nil, fmt.Errorf("%w: %s on %s is %d bytes, limit is %d", ErrFileTooLarge, path, share, info.Size(), c.maxReadSize)
	}

	guard = c.beginOperation()
	file, err := fs.Open(path)
	err = guard.finish(err)
	if err != nil {
		return nil, fmt.Errorf("open %s on %s: %w", path, share, err)
	}
	defer func() {
		guard := c.beginOperation()
		_ = guard.finish(file.Close())
	}()

	reader := io.Reader(file)
	if c.maxReadSize > 0 {
		reader = io.LimitReader(file, c.maxReadSize+1)
	}

	guard = c.beginOperation()
	data, err := io.ReadAll(reader)
	err = guard.finish(err)
	if err != nil && !errors.Is(err, io.EOF) {
		if os.IsPermission(err) {
			return nil, fmt.Errorf("read %s on %s: permission denied", path, share)
		}
		return nil, fmt.Errorf("read %s on %s: %w", path, share, err)
	}

	if c.maxReadSize > 0 && int64(len(data)) > c.maxReadSize {
		return nil, fmt.Errorf("%w: %s on %s exceeded the read limit", ErrFileTooLarge, path, share)
	}

	return data, nil
}
