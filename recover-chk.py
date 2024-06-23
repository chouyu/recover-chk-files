import re
import os
import shutil
import logging
from datetime import datetime
import dateutil.parser
import argparse
from PIL import Image
from PIL.ExifTags import TAGS
from pymediainfo import MediaInfo
from pillow_heif import register_heif_opener

# Register HEIF opener
register_heif_opener()

def setup_logging(log_path):
    """Set up logging configuration"""
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    logging.basicConfig(filename=log_path, level=logging.INFO, 
                        format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def get_file_signature(file_path, read_size=16):
    """Read and return the file signature"""
    with open(file_path, 'rb') as f:
        return f.read(read_size)

def identify_file_type(signature):
    """Identify file type based on its signature"""
    file_types = {
        b'\xFF\xD8\xFF': ('.jpg', get_jpeg_metadata),
        b'\x89PNG\r\n\x1A\n': ('.png', get_image_metadata),
        b'GIF8': ('.gif', get_image_metadata),
        b'%PDF': ('.pdf', None),
        b'PK\x03\x04': ('.zip', None),
        b'\x50\x4B\x03\x04\x14\x00\x06\x00': ('.docx', None),
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('.doc', None),
        b'\x52\x61\x72\x21\x1A\x07': ('.rar', None),
        b'\x1F\x8B\x08': ('.gz', None),
        b'BM': ('.bmp', get_image_metadata),
        b'\x00\x00\x01\x00': ('.ico', get_image_metadata),
        b'\x49\x44\x33': ('.mp3', None),
        b'\x25\x50\x44\x46': ('.pdf', None),
        b'\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A': ('.jp2', None),
        b'\x4F\x67\x67\x53': ('.ogg', None),
        b'\x38\x42\x50\x53': ('.psd', get_image_metadata),
        b'\x49\x49\x2A\x00': ('.tif', get_image_metadata),  # TIFF (little-endian)
        b'\x4D\x4D\x00\x2A': ('.tif', get_image_metadata),  # TIFF (big-endian)
        b'\x57\x41\x56\x45': ('.wav', None),
        b'\x25\x21\x50\x53': ('.eps', None),
        b'\x7B\x5C\x72\x74\x66': ('.rtf', None),
        b'\x00\x00\x00\x14ftypqt  ': ('.qt', get_video_metadata),  # QuickTime 文件识别
        b'\x00\x00\x00\x14\x66\x74\x79\x70': ('.mp4', get_video_metadata),
        b'\x00\x00\x00\x18\x66\x74\x79\x70\x6D\x70\x34': ('.mp4', get_video_metadata),
        b'\x00\x00\x00\x1C\x66\x74\x79\x70\x6D\x70\x34': ('.mp4', get_video_metadata),
        b'\x00\x00\x00\x1C\x66\x74\x79\x70\x69\x73\x6F\x6D': ('.mp4', get_video_metadata),
        b'\x00\x00\x00\x1C\x66\x74\x79\x70\x58\x41\x56\x43': ('.mp4', get_video_metadata),
        b'\x00\x00\x00\x20\x66\x74\x79\x70\x69\x73\x6F\x6D': ('.mp4', get_video_metadata),
        b'\x52\x49\x46\x46': ('.avi', get_video_metadata),  # AVI files start with "RIFF"
        b'\x1A\x45\xDF\xA3': ('.mkv', get_video_metadata),  # MKV files start with EBML
        b'\x46\x4C\x56\x01': ('.flv', get_video_metadata),
        b'\x4F\x67\x67\x53': ('.ogg', None),  # OGG files start with OggS
        b'\x66\x4C\x61\x43': ('.flac', None),  # FLAC files start with fLaC
        b'\x66\x74\x79\x70': ('.mov', get_video_metadata),  # MOV files start with 'ftyp'
        b'\x00\x00\x00\x14\x66\x74\x79\x70\x71\x74\x20\x20': ('.mov', get_video_metadata),
        b'\x00\x00\x00\x20\x66\x74\x79\x70\x33\x67\x70': ('.3gp', get_video_metadata),
        b'\x00\x00\x00\x20\x66\x74\x79\x70\x4D\x34\x56': ('.m4v', get_video_metadata),
        b'\x00\x00\x00\x1C\x66\x74\x79\x70\x4D\x53\x4E\x56': ('.mp4', get_video_metadata),
        b'\x00\x00\x00\x18\x66\x74\x79\x70\x68\x65\x69\x63': ('.heic', get_heic_metadata),
        b'\x42\x4D': ('.bmp', get_image_metadata),  # BMP files start with "BM"
        b'\x00\x01\x00\x00': ('.ico', get_image_metadata),  # ICO files start with 00 00 01 00
        b'\x4D\x5A': ('.exe', None),  # EXE files start with "MZ"
        b'\x25\x21\x50\x53': ('.ps', None),  # PS files start with "%!PS"
        b'\xFF\xFB': ('.mp3', None),  # MP3 files start with "FF FB"
        b'\x00\x00\x01\xB3': ('.mpg', get_video_metadata),  # MPEG files start with "00 00 01 B3"
        b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C': ('.asf', get_video_metadata),  # ASF files start with this long sequence
        b'\x38\x42\x50\x53': ('.psd', get_image_metadata),  # PSD files start with "8BPS"
        b'\x49\x44\x33': ('.mp3', None),  # MP3 files with ID3 tag start with "ID3"
        b'\x7F\x45\x4C\x46': ('.elf', None),  # ELF files start with "7F 45 4C 46"
        b'\x1F\x8B': ('.gz', None),  # GZ files start with "1F 8B"
        b'\x4D\x54\x68\x64': ('.mid', None),  # MIDI files start with "MThd"
        b'\x42\x4B\x47\x42': ('.bpg', None),  # BPG files start with "BKGD"
    }
    
    for sig, (ext, metadata_func) in file_types.items():
        if signature.startswith(sig):
            return ext, metadata_func
    return None, None

def get_jpeg_metadata(file_path):
    """Extract metadata from JPEG files"""
    try:
        with Image.open(file_path) as img:
            exif_data = img._getexif()
            metadata = {}
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if tag == 'DateTimeOriginal':
                        metadata['creation_time'] = value
                    elif tag == 'DateTime':
                        # If DateTimeOriginal is not available, use DateTime
                        if 'creation_time' not in metadata:
                            metadata['creation_time'] = value
            
            if 'creation_time' not in metadata:
                # If no time information is found, use the file's modification time
                metadata['creation_time'] = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y:%m:%d %H:%M:%S')

            metadata['width'], metadata['height'] = img.size
            metadata['format'] = 'JPEG'
            return metadata
    except Exception as e:
        logging.error(f"Error reading JPEG metadata for {file_path}: {str(e)}")
    return None

def get_video_metadata(file_path):
    """Extract metadata from video files"""
    try:
        media_info = MediaInfo.parse(file_path)
        for track in media_info.tracks:
            if track.track_type == "Video":
                creation_time = track.encoded_date or track.tagged_date or track.file_last_modification_date or datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y:%m:%d %H:%M:%S')
                if creation_time:
                    creation_time = dateutil.parser.parse(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                return {
                    'creation_time': creation_time,
                    'width': track.width,
                    'height': track.height,
                    'format': track.format
                }
    except Exception as e:
        logging.error(f"Error reading video metadata for {file_path}: {str(e)}")
    return None

def get_image_metadata(file_path):
    """Extract metadata from general image files"""
    try:
        with Image.open(file_path) as img:
            metadata = {
                'width': img.width,
                'height': img.height,
                'format': img.format
            }
            metadata['creation_time'] = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y:%m:%d %H:%M:%S')
            return metadata
    except Exception as e:
        logging.error(f"Error reading image metadata for {file_path}: {str(e)}")
    return None

def get_heic_metadata(file_path):
    """Extract metadata from HEIC files"""
    return get_image_metadata(file_path)

def process_files(input_folder, output_folder):
    """Process files to identify their types and move them accordingly"""
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    for dirpath, _, filenames in os.walk(input_folder):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            try:
                signature = get_file_signature(file_path)
                file_type, metadata_func = identify_file_type(signature)
                
                if not file_type:
                    logging.warning(f"Unknown file type for {file_path}. Skipping...")
                    continue
                
                file_metadata = metadata_func(file_path) if metadata_func else {}
                
                creation_time = file_metadata.get('creation_time')
                if creation_time:
                    creation_year = dateutil.parser.parse(creation_time).strftime('%Y')
                    target_folder = os.path.join(output_folder, creation_year)
                    if not os.path.exists(target_folder):
                        os.makedirs(target_folder)
                    target_path = os.path.join(target_folder, os.path.basename(file_path) + file_type)
                    shutil.move(file_path, target_path)
                    logging.info(f"Moved {file_path} to {target_path}")
                else:
                    logging.warning(f"Could not determine creation time for {file_path}. Skipping...")
            
            except Exception as e:
                logging.error(f"Error processing {file_path}: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process CHK files and recover original file types.")
    parser.add_argument("-src", required=True, help="Source path for CHK files")
    parser.add_argument("-dst", help="Destination path for recovered files (required unless using rename mode)")
    parser.add_argument("-rename", action="store_true", help="Use rename mode instead of copy mode")
    parser.add_argument("-log", help="Path for log file (default is source path)")

    args = parser.parse_args()

    if not args.rename and not args.dst:
        parser.error("Destination path (-dst) is required when not in rename mode")

    log_path = args.log if args.log else os.path.join(args.src, f"recovery_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    
    process_chk_files(args.src, args.dst, args.rename, log_path)

