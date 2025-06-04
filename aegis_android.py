import os
import subprocess

# Define the paths to adb and scrcpy in your lib folder
LIB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../lib'))
ADB = os.path.join(LIB_PATH, 'adb.exe')
SCRCPY = os.path.join(LIB_PATH, 'scrcpy.exe')

def check_connection():
    """Check if an Android device is connected."""
    result = subprocess.run([ADB, 'devices'], capture_output=True, text=True)
    print("Connected devices:\n" + result.stdout)

def extract_device_info():
    """Extract device properties and model info."""
    with open("../output/device_info.txt", "w") as f:
        subprocess.run([ADB, 'shell', 'getprop'], stdout=f)
    model = subprocess.check_output([ADB, 'shell', 'getprop', 'ro.product.model']).decode().strip()
    print(f"Device model: {model}")

def pull_data():
    """Pull common user data folders from the Android device."""
    paths = ["/sdcard/DCIM", "/sdcard/Download", "/sdcard/Documents"]
    for path in paths:
        subprocess.run([ADB, 'pull', path, "../output/"])

def advanced_data_capture():
    """Capture GPS/location, Wi-Fi logs, and record the screen."""
    # GPS & Location data (may require root)
    subprocess.run([ADB, 'pull', '/data/data/com.google.android.gms/files/', '../output/gps/'])
    # WiFi logs
    with open("../output/wifi_logs.txt", "w") as f:
        subprocess.run([ADB, 'shell', 'dumpsys', 'wifi'], stdout=f)
    # Screen recording (30s limit)
    subprocess.run([SCRCPY, '-r', '../output/screen_record.mp4', '--time-limit=30'])

if __name__ == "__main__":
    check_connection()
    extract_device_info()
    pull_data()
    advanced_data_capture()
