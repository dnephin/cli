/*Package external supports extending the cli with external binaries.

To add an external command:
 - create a directory with the name of the command in either ~/.docker/commands/ or
   /etc/docker/commands/
 - in the directory add an executable with the same name as the directory
 - add a manifest.json to the directory. See the manifest type in this file for
   structure.

*/
package external

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/config"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const (
	userCommandPathDir = "commands"
	systemCommandPath  = "/etc/docker/commands"
	manifestFilename   = "manifest.json"
)

type manifest struct {
	// Version of the manifest, ignored for now
	Version string
	// Short description of the command, used in the root command help text to
	// list commands.
	Short string
}

func readManifest(dir string) (manifest, error) {
	file, err := ioutil.ReadFile(filepath.Join(dir, manifestFilename))
	if err != nil {
		return manifest{}, errors.Wrapf(err, "missing manifest")
	}
	manifest := manifest{}
	err = json.Unmarshal(file, &manifest)
	return manifest, errors.Wrapf(err, "invalid manifest")
}

// Command looks for an external command by name, and returns a runner for the
// command. If no command is found returns nil.
func Command(args []string) (func() error, error) {
	if len(args) == 0 {
		return nil, nil
	}
	name, args := args[0], args[1:]

	for _, cmdpath := range commandPaths() {
		fullpath := filepath.Join(cmdpath, name)
		if exists(fullpath) {
			return cmdFromPath(fullpath, args)
		}
	}
	return nil, nil
}

func commandPaths() []string {
	return []string{
		filepath.Join(config.Dir(), userCommandPathDir),
		systemCommandPath,
	}
}

func exists(fullpath string) bool {
	stat, err := os.Stat(fullpath)
	return err == nil && stat.IsDir()
}

func cmdFromPath(fullpath string, args []string) (func() error, error) {
	// TODO: use manifest to support alternative name for binary?
	binary := filepath.Join(fullpath, filepath.Base(fullpath))

	if runtime.GOOS == "windows" {
		return func() error {
			cmd := exec.Command(binary, args...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return wrapCommandError(cmd.Run())
		}, nil
	}

	return func() error {
		args := append([]string{filepath.Base(fullpath)}, args...)
		return syscall.Exec(binary, args, os.Environ())
	}, nil
}

func wrapCommandError(err error) error {
	if err == nil {
		return nil
	}
	if exiterr, ok := err.(*exec.ExitError); ok {
		if procExit, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			return cli.StatusError{StatusCode: procExit.ExitStatus()}
		}
	}
	return err
}

// Help returns stubbed cobra.Command used to list external commands
// in help text for the root commands.
func Help() []cobra.Command {
	cmds := []cobra.Command{}
	for _, cmdpath := range commandPaths() {
		files, err := ioutil.ReadDir(cmdpath)
		if err != nil {
			// TODO: log error?
			continue
		}
		for _, stat := range files {
			if !stat.IsDir() {
				continue
			}
			manifest, err := readManifest(filepath.Join(cmdpath, stat.Name()))
			if err != nil {
				// TODO: log error, or make the manifest optional?
				continue
			}
			cmds = append(cmds, cobra.Command{
				Use:   stat.Name(),
				Short: manifest.Short,
			})
		}
	}
	return cmds
}
