# pwfz

`pwfz` is a command-line tool that allows you to search for passwords in your [Passwork](https://passwork.pro/) vault using `fzf`.

## Installation

You can build `pwfz` from source:

```bash
go build
```

Alternatively, you can download a pre-built binary from the [releases page](https://github.com/denislavrushko/pwfz/releases).

## Configuration

`pwfz` is configured using environment variables:

-   `PASSWORK_BASE_URL`: The URL of your Passwork instance (e.g., `https://password.example.com/api/v4`). **This is required.**
-   `PASSWORK_API_KEY`: Your Passwork API key. **This is required.**
-   `FZF_BIN`: The path to the `fzf` binary (defaults to `fzf`).
-   `CLIP_BIN`: The path to the clipboard command (e.g., `pbcopy`, `xclip`, `wl-copy`). The tool attempts to auto-detect the appropriate command for your system.

## Usage

To search for a password, run `pwfz` with a search query:

```bash
pwfz my-password
```

This will open `fzf` with a list of matching passwords. Select a password to copy it to your clipboard.

## Dependencies

-   [fzf](httpss://github.com/junegunn/fzf) is required to be installed and available in your `$PATH`.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
