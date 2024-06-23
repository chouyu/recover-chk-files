import re
import os
import shutil
import logging
from datetime import datetime
import subprocess
import json
from PIL import Image
from PIL.ExifTags import TAGS
from pymediainfo import MediaInfo
from pillow_heif import register_heif_opener
import argparse

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
        b'\x00\x00\x01\x00': ('.ico', None),
        b'\x49\x44\x33': ('.mp3', None),
        b'\x25\x50\x44\x46': ('.pdf', None),
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('.doc', None),
        b'\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A': ('.jp2', None),
        b'\x4F\x67\x67\x53': ('.ogg', None),
        b'\x38\x42\x50\x53': ('.psd', None),
        b'\x49\x49\x2A\x00': ('.tif', get_image_metadata),  # TIFF (little-endian)
        b'\x4D\x4D\x00\x2A': ('.tif', get_image_metadata),  # TIFF (big-endian)
        b'\x57\x41\x56\x45': ('.wav', None),
        b'\x25\x21\x50\x53': ('.eps', None),
        b'\x7B\x5C\x72\x74\x66': ('.rtf', None),
        b'\x00\x00\x00\x14ftypqt  ': ('.qt', get_video_metadata),  # 添加 QuickTime 文件识别
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
            if track.track_type == "General":
                duration = float(track.duration) / 1000 if track.duration else None
                creation_time = track.encoded_date or track.tagged_date
                format = track.format
                logging.info(f"Video format detected: {format}")
                return {
                    'duration': duration,
                    'creation_time': creation_time,
                    'format': format
                }
    except Exception as e:
        logging.error(f"Error reading video metadata for {file_path}: {str(e)}")
    return None

def get_image_metadata(file_path):
    """Extract metadata from image files"""
    try:
        with Image.open(file_path) as img:
            metadata = {}
            exif_data = img._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if tag == 'DateTimeOriginal':
                        metadata['creation_time'] = value
            metadata['width'], metadata['height'] = img.size
            metadata['format'] = img.format
            return metadata
    except Exception as e:
        logging.error(f"Error reading image metadata for {file_path}: {str(e)}")
    return None

def get_heic_metadata(file_path):
    """Extract metadata from HEIC files"""
    try:
        with Image.open(file_path) as img:
            metadata = {}
            exif_data = img.getexif()
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
            metadata['format'] = 'HEIC'
            return metadata
    except Exception as e:
        logging.error(f"Error reading HEIC metadata for {file_path}: {str(e)}")
    return None

def process_chk_files(src_path, dst_path, rename_mode, log_path):
    """Process CHK files and recover original file types"""
    setup_logging(log_path)
    logging.info(f"Processing CHK files in {src_path}")
    
    for filename in os.listdir(src_path):
        if filename.upper().endswith('.CHK'):
            file_path = os.path.join(src_path, filename)
            file_size = os.path.getsize(file_path)
            
            if file_size == 0:
                logging.warning(f"Skipping empty file: {filename}")
                continue
            
            signature = get_file_signature(file_path)
            file_type, metadata_func = identify_file_type(signature)
            
            if not file_type:
                logging.warning(f"Unknown file type for {filename}")
                continue
            
            new_filename = os.path.splitext(filename)[0] + file_type
            if rename_mode:
                new_file_path = os.path.join(src_path, new_filename)
            else:
                new_file_path = os.path.join(dst_path, new_filename)
            
            if os.path.exists(new_file_path):
                logging.warning(f"File {new_filename} already exists, skipping")
                continue
            
            try:
                if rename_mode:
                    os.rename(file_path, new_file_path)
                    logging.info(f"Renamed: {filename} -> {new_filename}")
                else:
                    shutil.copy2(file_path, new_file_path)
                    logging.info(f"Copied: {filename} -> {new_filename}")

                # Read metadata
                metadata = None
                if metadata_func:
                    try:
                        metadata = metadata_func(new_file_path)
                    except Exception as e:
                        logging.error(f"Error reading metadata for {new_filename}: {str(e)}")

                if metadata:
                    if 'duration' in metadata and metadata['duration'] is not None:
                        try:
                            expected_size = int(float(metadata['duration']) * 1000000)
                            size_ratio = file_size / expected_size
                            if size_ratio > 2 or size_ratio < 0.5:
                                logging.info(f"Possible incorrect file size for {new_filename}. Expected: {expected_size}, Actual: {file_size}")
                            else:
                                logging.info(f"File size for {new_filename} seems reasonable. Expected: {expected_size}, Actual: {file_size}")
                        except (ValueError, TypeError) as e:
                            logging.error(f"Error calculating file size for {new_filename}: {str(e)}")
                    
                    creation_time = None
                    if 'creation_time' in metadata and metadata['creation_time']:
                        try:
                            # For JPEG and HEIC files, the time format may contain additional text
                            if file_type.lower() in ['.jpg', '.jpeg', '.heic']:
                                # Remove possible non-ASCII characters
                                cleaned_time = re.sub(r'[^\x00-\x7F]+', '', metadata['creation_time'])
                                # Try to extract the standard date-time format
                                match = re.search(r'(\d{4}[:/-]\d{2}[:/-]\d{2} \d{2}:\d{2}:\d{2})', cleaned_time)
                                if match:
                                    creation_time = datetime.strptime(match.group(1), '%Y:%m:%d %H:%M:%S')
                                else:
                                    # If unable to match the standard format, try other possible formats
                                    creation_time = dateutil.parser.parse(cleaned_time, fuzzy=True)
                            else:
                                creation_time = dateutil.parser.parse(metadata['creation_time'])
                            
                            logging.info(f"Parsed creation time for {new_filename}: {creation_time}")
                        except Exception as e:
                            logging.error(f"Error parsing creation time from metadata for {new_filename}: {str(e)}")
                            logging.error(f"Original creation time string: {metadata['creation_time']}")

                    if creation_time is None:
                        # Use the source file's modification time
                        creation_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                        logging.info(f"Using source file modification time for {new_filename}: {creation_time}")

                    try:
                        os.utime(new_file_path, (creation_time.timestamp(), creation_time.timestamp()))
                        logging.info(f"Updated creation time for {new_filename} to {creation_time}")
                    except Exception as e:
                        logging.error(f"Error updating creation time for {new_filename}: {str(e)}")
                    
                    if 'width' in metadata and 'height' in metadata:
                        logging.info(f"Image dimensions for {new_filename}: {metadata['width']}x{metadata['height']}")
                        if file_type in ['.jpg', '.jpeg', '.heic'] and (metadata['width'] < 100 or metadata['height'] < 100):
                            logging.warning(f"Possible thumbnail detected for {new_filename}. Dimensions: {metadata['width']}x{metadata['height']}")
                    
                    if 'format' in metadata:
                        logging.info(f"Image format for {new_filename}: {metadata['format']}")

            except Exception as e:
                logging.error(f"Error processing {filename}: {str(e)}")

    logging.info("CHK file processing completed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process CHK files and recover original file types.")
    parser.add_argument("-src", required=True, help="Source path for CHK files")
    parser.add_argument("-dst", help="Destination path for recovered files (not required in rename mode)")
    parser.add_argument("-rename", action="store_true", help="Use rename mode instead of copy mode")
    parser.add_argument("-log", help="Path for log file (default is source path)")
    
    args = parser.parse_args()
    
    if not args.rename and not args.dst:
        parser.error("Destination path (-dst) is required when not in rename mode")
    
    log_path = args.log if args.log else os.path.join(args.src, f"recovery_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    
    process_chk_files(args.src, args.dst, args.rename, log_path)
