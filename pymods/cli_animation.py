import time
import threading
import sys
import itertools

class CLIAnimation:
    def __init__(self):
        self.is_running = False
        self.animation_thread = None
        
    def spinner_animation(self, message="Processing"):
        """Realistic spinner animation"""
        spinner = itertools.cycle(['|', '/', '-', '\\'])
        while self.is_running:
            sys.stdout.write(f'\r{message}... {next(spinner)}')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * (len(message) + 10) + '\r')
        sys.stdout.flush()
    
    def dots_animation(self, message="Loading"):
        """Realistic dots animation"""
        dots = itertools.cycle(['', '.', '..', '...'])
        while self.is_running:
            sys.stdout.write(f'\r{message}{next(dots)}   ')
            sys.stdout.flush()
            time.sleep(0.5)
        sys.stdout.write('\r' + ' ' * (len(message) + 10) + '\r')
        sys.stdout.flush()
    
    def progress_bar(self, message="Processing", width=30):
        """Realistic progress bar simulation"""
        progress = 0
        while self.is_running and progress < width:
            filled = '█' * progress
            empty = '░' * (width - progress)
            percent = int((progress / width) * 100)
            sys.stdout.write(f'\r{message}: [{filled}{empty}] {percent}%')
            sys.stdout.flush()
            time.sleep(0.2)
            progress += 1
        
        if self.is_running:
            # Complete the bar
            filled = '█' * width
            sys.stdout.write(f'\r{message}: [{filled}] 100%')
            sys.stdout.flush()
            time.sleep(0.3)
        
        sys.stdout.write('\r' + ' ' * (len(message) + width + 15) + '\r')
        sys.stdout.flush()
    
    def start_animation(self, animation_type="spinner", message="Processing"):
        """Start the specified animation"""
        if self.is_running:
            return
            
        self.is_running = True
        
        if animation_type == "spinner":
            self.animation_thread = threading.Thread(
                target=self.spinner_animation, 
                args=(message,)
            )
        elif animation_type == "dots":
            self.animation_thread = threading.Thread(
                target=self.dots_animation, 
                args=(message,)
            )
        elif animation_type == "progress":
            self.animation_thread = threading.Thread(
                target=self.progress_bar, 
                args=(message,)
            )
        
        self.animation_thread.daemon = True
        self.animation_thread.start()
    
    def stop_animation(self):
        """Stop the current animation"""
        self.is_running = False
        if self.animation_thread:
            self.animation_thread.join(timeout=1)
            self.animation_thread = None

# Context manager for easy usage
class LoadingAnimation:
    def __init__(self, message="Processing", animation_type="spinner"):
        self.animator = CLIAnimation()
        self.message = message
        self.animation_type = animation_type
    
    def __enter__(self):
        self.animator.start_animation(self.animation_type, self.message)
        return self.animator
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.animator.stop_animation()

# Helper functions for direct usage
def show_loading(func, message="Processing", animation_type="spinner"):
    """Decorator to show loading animation during function execution"""
    def wrapper(*args, **kwargs):
        with LoadingAnimation(message, animation_type):
            return func(*args, **kwargs)
    return wrapper

def simulate_ollama_wait(message="Waiting for Ollama response"):
    """Simulate waiting for Ollama with realistic animation"""
    with LoadingAnimation(message, "dots"):
        time.sleep(2)  # Simulate actual waiting time
