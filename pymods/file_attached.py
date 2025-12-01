import json
import mimetypes
from pathlib import Path
import base64

# module for attachig and give acces of a file to the ollama model
import os
from .cli_animation import LoadingAnimation, show_loading

class FileAttacher:
    def __init__(self):
        self.supported_text_types = {'.txt', '.py', '.js', '.html', '.css', '.json', '.xml', '.md', '.yml', '.yaml', '.csv', '.log', '.tsv', '.conf', '.ini'}
        self.supported_image_types = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
        
    def read_file(self, file_path):
        """Read and return file content based on file type"""
        try:
            with LoadingAnimation("Reading file", "spinner"):
                path = Path(file_path)
                if not path.exists():
                    return {"error": f"File not found: {file_path}"}
                
                file_ext = path.suffix.lower()
                mime_type = mimetypes.guess_type(file_path)[0]
                
                if file_ext in self.supported_text_types:
                    return self._read_text_file(path)
                elif file_ext in self.supported_image_types:
                    return self._read_image_file(path)
                else:
                    return self._read_binary_file(path)
                    
        except Exception as e:
            return {"error": f"Error reading file: {str(e)}"}
    
    def _read_text_file(self, path):
        """Read text-based files"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            return {
                "type": "text",
                "content": content,
                "size": path.stat().st_size,
                "extension": path.suffix
            }
        except UnicodeDecodeError:
            return self._read_binary_file(path)
    
    def _read_image_file(self, path):
        """Read image files and encode as base64"""
        with LoadingAnimation("Encoding image", "progress"):
            with open(path, 'rb') as f:
                content = base64.b64encode(f.read()).decode('utf-8')
            return {
                "type": "image",
                "content": content,
                "size": path.stat().st_size,
                "extension": path.suffix
            }
    
    def _read_binary_file(self, path):
        """Read binary files and encode as base64"""
        with LoadingAnimation("Processing binary file", "progress"):
            with open(path, 'rb') as f:
                content = base64.b64encode(f.read()).decode('utf-8')
            return {
                "type": "binary",
                "content": content,
                "size": path.stat().st_size,
                "extension": path.suffix
            }
    
    def list_directory(self, dir_path):
        """List files and directories in given path"""
        try:
            with LoadingAnimation("Scanning directory", "dots"):
                path = Path(dir_path)
                if not path.exists():
                    return {"error": f"Directory not found: {dir_path}"}
                
                items = []
                for item in path.iterdir():
                    items.append({
                        "name": item.name,
                        "path": str(item),
                        "is_dir": item.is_dir(),
                        "size": item.stat().st_size if item.is_file() else None
                    })
                return {"items": items}
        except Exception as e:
            return {"error": f"Error listing directory: {str(e)}"}
    
    def get_file_info(self, file_path):
        """Get detailed file information"""
        try:
            path = Path(file_path)
            if not path.exists():
                return {"error": f"File not found: {file_path}"}
            
            stat = path.stat()
            return {
                "name": path.name,
                "path": str(path),
                "size": stat.st_size,
                "extension": path.suffix,
                "mime_type": mimetypes.guess_type(file_path)[0],
                "modified": stat.st_mtime,
                "is_readable": os.access(path, os.R_OK),
                "is_writable": os.access(path, os.W_OK)
            }
        except Exception as e:
            return {"error": f"Error getting file info: {str(e)}"}

# Usage functions with animation
@show_loading(message="Attaching file", animation_type="spinner")
def attach_file(file_path):
    """Main function to attach a file for AI model interaction"""
    attacher = FileAttacher()
    return attacher.read_file(file_path)

@show_loading(message="Browsing directory", animation_type="dots")
def browse_directory(dir_path="."):
    """Browse directory contents"""
    attacher = FileAttacher()
    return attacher.list_directory(dir_path)

def file_info(file_path):
    """Get file information"""
    attacher = FileAttacher()
    return attacher.get_file_info(file_path)