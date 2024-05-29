import os
import sys
import subprocess
import argparse
import logging
import hashlib
import random
from dataclasses import dataclass
from abc import ABC, abstractmethod


class FileCreator(ABC):
    @abstractmethod
    def create_file(self, file_path, sizeKB):
        pass

class FileCreatorWithRandomData(FileCreator):
    def __init__(self):
        self._chunk_size = 4096
    
    @property
    def chunk_size(self):
        return self._chunk_size
    
    @chunk_size.setter
    def chunk_size(self, value):
        self._chunk_size = value
    
    def create_file(self, file_path, sizeKB):
        with open(file_path, 'wb') as dummy_file:
            remaining_size = sizeKB * 1024 

            while remaining_size > 0:
                if remaining_size < self.chunk_size:
                    self.chunk_size = remaining_size
                random_bytes = os.urandom(self.chunk_size)
                dummy_file.write(random_bytes)
                remaining_size -= self.chunk_size

class FileCreatorWithZeros(FileCreator):
    def __init__(self):
       pass
     
    def create_file(self, file_path, sizeKB):
        command     = ["dd",  "if=/dev/zero", f"of={file_path}", "bs=1K", f"count={sizeKB}"]
        process     = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return_code = process.wait()

        if return_code != 0:
            error_message = process.stderr.read().decode().strip()
            raise RuntimeError(f"Ошибка при создании файла c помощью dd: {error_message}")





class FileHasher(ABC):
    @abstractmethod
    def calculate_hash(self, file_path):
        pass

class FileHasherMD5(FileHasher):
    def __init__(self):
        self._chunk_size = 4096
    
    @property
    def chunk_size(self):
        return self._chunk_size

    @chunk_size.setter
    def chunk_size(self, value):
        self._chunk_size = value

    def calculate_hash(self, file_path):
        md5_hash = hashlib.md5()

        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(self.chunk_size), b""):
                md5_hash.update(chunk)

        return md5_hash.hexdigest()



class ISOCreator(ABC):
    @abstractmethod
    def create_iso_file(self, source, output):
        pass

class ISOCreatorGENISOIMAGE(ISOCreator):
    def __init__(self):
        pass

    def create_iso_file(self, source, output):
        command     = ['genisoimage', '-o', output,  source]
        process     = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return_code = process.wait()

        if return_code != 0:
            error_message = process.stderr.read().decode().strip()
            raise RuntimeError(f"Ошибка при создании ISO файла c помощью genisoimage: {error_message}")



class Logger:
    def __init__(self, log_dir, log_filename, level=logging.INFO):
        os.makedirs(log_dir, exist_ok=True)

        self.log_file_path = os.path.join(log_dir, log_filename)

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(level)

        file_handler = logging.FileHandler(self.log_file_path)
        file_handler.setLevel(level)

        formatter = logging.Formatter('%(asctime)s  %(levelname)s  %(message)s')
        file_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)

    def log(self, message, level=logging.INFO):
        if level == logging.INFO:
            self.logger.info(message)
        elif level == logging.WARNING:
            self.logger.warning(message)
        elif level == logging.ERROR:
            self.logger.error(message)
        elif level == logging.CRITICAL:
            self.logger.critical(message)
        else:
            raise ValueError("Unsupported logger level")

    def get_logfile_path(self):
        return self.log_file_path





@dataclass
class IsoFile:
    name:   str
    size:   int
    md5:    str

    def __str__(self) -> str:
        return f"{self.name:<12} <> {self.size:<12} <> {self.md5}"





class ISOFiller:
    def __init__(self, device, percent, file_creator: FileCreator, iso_creator: ISOCreator, hash_calculator: FileHasher, logger):
        self.hash_calctulator   = hash_calculator()
        self.file_creator       = file_creator()
        self.iso_creator        = iso_creator()
        self.percent            = percent
        self.device             = os.path.abspath(device)
        self.created_files      = []
        self.logger             = logger("/var/logs/isofiller", "logs.log")
        self.temp_dir           = "/tmp/isofiller"

    def remove_file(self, file_path):
        os.remove(file_path)
    
    def get_device_size(self):
        statvfs = os.statvfs(self.device)
        return statvfs.f_frsize * statvfs.f_blocks

    def get_device_free_space(self):
        statvfs = os.statvfs(self.device)
        return statvfs.f_frsize * statvfs.f_bfree
    
    def get_file_size(self, file_path):
        return os.path.getsize(file_path)

    def print_created_files_data(self):
        for file_data in self.created_files:
            print(file_data)

    def get_required_fill_size(self):
        total_size  = self.get_device_size()
        free_space  = self.get_device_free_space()
        target_size = int(total_size * (self.percent / 100))
        return int(target_size - (total_size - free_space))


    def get_random_size_less_150M(self):
        required_size = self.get_required_fill_size()
        if required_size > 157_286_400: # 150mb
            required_size = 157_286_400
        random_size = random.randint(1, required_size)
        return random_size


    def create_temp_directory(self):
        os.makedirs(self.temp_dir, exist_ok=True)


    def save_iso_data(self, iso_path):
        self.created_files.append(
            IsoFile(
                name    = os.path.basename(iso_path),
                size    = os.path.getsize(iso_path),
                md5     = self.hash_calctulator.calculate_hash(iso_path),
            )
        )


    


    def fill(self):
        required_fill_size = self.get_required_fill_size()

        if required_fill_size < 4096:
            total = self.get_device_size()
            free  = self.get_device_free_space()
            sys.exit(f"Already filled by {(total-free)*100/total:.2f}%")

        self.create_temp_directory()
        file_number = 0

        self.logger.log(f"Начинаю заполнение устройства {self.device} до {self.percent}%")


        while self.get_required_fill_size() > 0:
            random_size_bytes = self.get_random_size_less_150M()
            random_size_kb    = int(random_size_bytes/1024)
            source_file       = f"{self.temp_dir}/{file_number}"
            iso_file          = f"{self.device}/file_{file_number}.iso"


            try:
                self.file_creator.create_file(source_file, random_size_kb)
            except Exception as e:
                self.logger.log(f"Exception while creating dummy-file: {e}", logging.ERROR)
                sys.exit(f'Ошибка при создании временного файла. Лог -> {self.logger.get_logfile_path()}')


            try:
                self.iso_creator.create_iso_file(source_file, iso_file)
            except Exception as e:
                self.logger.log(f"Exception while creating iso-file: {e}", logging.ERROR)
                if "genisoimage: No space left on device" in str(e) and self.get_device_free_space() < 4096:
                    break
                else:
                    sys.exit(f'Ошибка при создании iso файла. Логи -> {self.logger.get_logfile_path()}')
            else:
                self.save_iso_data(iso_file)
                self.logger.log(f"[{self.device}] Добавлен файл: {str(self.created_files[-1])}")
                file_number += 1
            finally:
                os.remove(source_file)

        self.logger.log(f"Заполнение устройства {self.device} завершено")
            
            

        


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('device', type=str, help='Path to the device')
    parser.add_argument('percent', type=float, help='Percent to fill device')
    
    args = parser.parse_args()
    
    if not os.path.ismount(args.device):
        sys.exit(f'Device {args.device} is not mounted')
    
    if args.percent < 0.0 or args.percent > 100.0:
        sys.exit(f'Fill percent out of bounds')
    
    return args.device, args.percent


if __name__ == "__main__":
    device, percent = get_args()

    filler = ISOFiller(
        device          = device,
        percent         = percent,
        file_creator    = FileCreatorWithZeros,
        iso_creator     = ISOCreatorGENISOIMAGE,
        hash_calculator = FileHasherMD5,
        logger          = Logger,
    )
    
    filler.fill()
    filler.print_created_files_data()

    
    
    