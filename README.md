# CHK File Recovery Script

This script processes CHK files and attempts to recover their original file types based on file signatures. It can rename or copy the files to a specified destination with appropriate file extensions and metadata.

## Features

- Identifies file types based on file signatures.
- Recovers and renames or copies CHK files with appropriate file extensions.
- Extracts and logs metadata such as creation time, duration, and dimensions for supported file types.
- Supports a variety of file types including images, videos, documents, and archives.

## Supported File Types

The script can identify and process a wide range of file types, including but not limited to:

- JPEG (`.jpg`)
- PNG (`.png`)
- GIF (`.gif`)
- PDF (`.pdf`)
- ZIP (`.zip`)
- DOC/DOCX (`.doc`, `.docx`)
- RAR (`.rar`)
- BMP (`.bmp`)
- ICO (`.ico`)
- MP3 (`.mp3`)
- JP2 (`.jp2`)
- OGG (`.ogg`)
- PSD (`.psd`)
- TIFF (`.tif`)
- WAV (`.wav`)
- EPS (`.eps`)
- RTF (`.rtf`)
- MOV (`.mov`)
- MP4 (`.mp4`)
- AVI (`.avi`)
- MKV (`.mkv`)
- FLV (`.flv`)
- FLAC (`.flac`)
- 3GP (`.3gp`)
- M4V (`.m4v`)
- HEIC (`.heic`)
- EXE (`.exe`)
- PS (`.ps`)
- MPG (`.mpg`)
- ASF (`.asf`)
- ELF (`.elf`)
- GZ (`.gz`)

## Requirements

- Python 3.6 or higher
- Required Python packages:
  - `pillow`
  - `pymediainfo`
  - `pillow_heif`

Install the required packages using pip:

```sh
pip install pillow pymediainfo pillow_heif
```

## Usage

### Command-Line Arguments

- `-src` (required): Source path for CHK files.
- `-dst` (optional): Destination path for recovered files (required unless using rename mode).
- `-rename` (optional): Use rename mode instead of copy mode.
- `-log` (optional): Path for log file (default is the source path).

### Examples

1. **Rename mode:**

   ```sh
   python recover_chk_files.py -src /path/to/chk/files -rename
   ```

2. **Copy mode:**

   ```sh
   python recover_chk_files.py -src /path/to/chk/files -dst /path/to/destination
   ```

3. **Custom log file:**

   ```sh
   python recover_chk_files.py -src /path/to/chk/files -dst /path/to/destination -log /path/to/logfile.txt
   ```

## Logging

The script logs its operations, including errors and metadata extraction results, to a specified log file. If no log file is specified, it defaults to creating a log file in the source path with a timestamped filename.

## Metadata Extraction

The script extracts metadata from supported file types and logs information such as:

- Creation time
- Duration (for video and audio files)
- Dimensions (for image files)
- Format

## License

This project is licensed under the GPL License.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Acknowledgements

- File signatures were sourced from [Gary Kessler's File Signature Table](https://www.garykessler.net/library/file_sigs.html).

