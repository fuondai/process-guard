import os
import subprocess
import shutil
import sys

# --- Cấu hình --- #
SCRIPT_NAME = "test_harness.py"
EXE_NAME = "TestHarness"
# Tệp bổ sung cần đưa vào, định dạng "nguồn;đích"
# Ở đây, benign_script.ps1 sẽ được đặt vào thư mục gốc khi exe chạy.
ADDITIONAL_FILES = [
    f"benign_script.ps1{os.pathsep}."
]

# --- Hàm trợ giúp --- #
def install_pyinstaller():
    """Kiểm tra và cài đặt PyInstaller nếu cần."""
    print(">>> Kiểm tra và cài đặt PyInstaller...")
    try:
        import PyInstaller
        print("PyInstaller đã được cài đặt.")
    except ImportError:
        print("PyInstaller chưa được cài đặt. Đang tiến hành cài đặt...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
            print("Cài đặt PyInstaller thành công.")
        except subprocess.CalledProcessError as e:
            print(f"LỖI: Không thể cài đặt PyInstaller. Lỗi: {e}")
            sys.exit(1)

def clean_build_files():
    """Dọn dẹp các tệp và thư mục build cũ."""
    print(">>> Dọn dẹp các tệp build cũ...")
    for item in ["build", "dist", f"{EXE_NAME}.spec"]:
        if os.path.isdir(item):
            try:
                shutil.rmtree(item)
                print(f"Đã xóa thư mục: {item}")
            except OSError as e:
                print(f"Lỗi khi xóa thư mục {item}: {e}")
        elif os.path.isfile(item):
            try:
                os.remove(item)
                print(f"Đã xóa tệp: {item}")
            except OSError as e:
                print(f"Lỗi khi xóa tệp {item}: {e}")

def build_executable():
    """Chạy PyInstaller để tạo tệp thực thi."""
    if not os.path.exists(SCRIPT_NAME):
        print(f"LỖI: Không tìm thấy tệp kịch bản chính '{SCRIPT_NAME}'.")
        sys.exit(1)

    print(f">>> Bắt đầu quá trình build cho {SCRIPT_NAME}...")
    
    command = [
        "pyinstaller",
        "--onefile",
        "--name", EXE_NAME,
    ]

    for file_map in ADDITIONAL_FILES:
        command.extend(["--add-data", file_map])
    
    command.append(SCRIPT_NAME)

    print(f"Chạy lệnh: {' '.join(command)}")
    
    try:
        subprocess.check_call(command)
        print("\n>>> Build thành công!")
        print(f"Tệp thực thi được tạo tại: {os.path.abspath(os.path.join('dist', f'{EXE_NAME}.exe'))}")
    except subprocess.CalledProcessError as e:
        print(f"\nLỖI: Quá trình build thất bại. Lỗi: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print("\nLỖI: Lệnh 'pyinstaller' không được tìm thấy. Hãy chắc chắn rằng PyInstaller đã được cài đặt và nằm trong PATH của hệ thống.")
        sys.exit(1)

# --- Luồng chính --- #
if __name__ == "__main__":
    clean_build_files()
    install_pyinstaller()
    build_executable()
    print("\n>>> Quá trình hoàn tất.")
