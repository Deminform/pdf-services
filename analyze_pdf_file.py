import os
import subprocess
import pikepdf
import fitz  # PyMuPDF
import hashlib
from colorama import init, Fore, Style
from peepdf.PDFCore import PDFParser
from peepdf.JSAnalysis import analyzeJavaScript

# Инициализация Colorama
init(autoreset=True)


def check_pdf_with_qpdf(pdf_path):
    """
    Проверяет целостность PDF-файла с помощью QPDF.
    """
    try:
        print(Fore.CYAN + f"\nRunning QPDF check on: {pdf_path}")
        result = subprocess.run(['qpdf', '--check', pdf_path], capture_output=True, text=True)
        if result.returncode == 0:
            print(Fore.GREEN + "QPDF: PDF is structurally sound.")
        else:
            print(Fore.RED + "QPDF: Issues found in PDF structure.")
            print(Fore.RED + result.stderr)
    except FileNotFoundError:
        print(Fore.RED + "Error: QPDF is not installed or not found in system PATH.")
    except Exception as e:
        print(Fore.RED + f"An error occurred while checking with QPDF: {e}")


def analyze_metadata_with_pikepdf(pdf_path):
    """
    Анализирует метаданные PDF-файла с помощью pikepdf.
    """
    try:
        print(Fore.CYAN + f"\nAnalyzing metadata with pikepdf for: {pdf_path}")
        with pikepdf.open(pdf_path) as pdf:
            metadata = pdf.docinfo
            if metadata:
                print(Fore.YELLOW + "Metadata found:")
                for key, value in metadata.items():
                    print(Fore.YELLOW + f"{key}: {value}")
            else:
                print(Fore.RED + "No metadata found.")
    except Exception as e:
        print(Fore.RED + f"An error occurred while analyzing with pikepdf: {e}")


def analyze_binary_structure(pdf_path):
    """
    Низкоуровневый анализ бинарной структуры PDF-файла.
    """
    try:
        with open(pdf_path, 'rb') as f:
            data = f.read()

        # Хеширование данных для базовой проверки
        file_hash = hashlib.sha256(data).hexdigest()
        print(Fore.YELLOW + f"SHA-256 хеш файла: {file_hash}")

        # Простейшая проверка на присутствие стандартных PDF меток
        if b'%PDF-' not in data:
            print(Fore.RED + "Это не стандартный PDF-файл, отсутствует начальная метка %PDF-.")

        # Анализ на наличие скрытых объектов или потока
        print(Fore.CYAN + "Анализ на наличие скрытых объектов:")
        if b'ObjStm' in data:
            print(Fore.YELLOW + "Найден объектный поток (ObjStm), который может содержать скрытые объекты.")
        if b'/Encrypt' in data:
            print(Fore.YELLOW + "Файл зашифрован (Encrypt), что может указывать на попытку скрыть данные.")

        # Проверка концов файла
        if not data.rstrip().endswith(b'%%EOF'):
            print(Fore.RED + "Файл может быть поврежден, отсутствует корректная метка окончания (%%EOF).")
        else:
            print(Fore.GREEN + "Метка окончания (%%EOF) присутствует.")
    except Exception as e:
        print(Fore.RED + f"Ошибка при анализе бинарной структуры PDF: {e}")


def analyze_pdf_objects(pdf_path):
    """
    Глубокий анализ объектов PDF-файла.
    """
    try:
        doc = fitz.open(pdf_path)
        print(Fore.CYAN + f"\nPDF '{pdf_path}' открыт, количество страниц: {doc.page_count}\n")

        # Анализ объектов
        for i in range(len(doc)):
            page = doc[i]
            for img in page.get_images(full=True):
                xref = img[0]
                base_image = doc.extract_image(xref)
                image_bytes = base_image["image"]
                image_hash = hashlib.md5(image_bytes).hexdigest()
                print(Fore.YELLOW + f"  Объект изображения (xref: {xref}) - MD5 хеш: {image_hash}")
                print(Fore.YELLOW + f"  Детали изображения: {base_image}")

            # Анализируем текстовые объекты и их шрифты
            text_instances = page.get_text("dict")
            for block in text_instances["blocks"]:
                if block["type"] == 0:  # Текстовый блок
                    print(Fore.GREEN + f"Текстовый блок с содержимым: {block['lines']}")
                    for line in block['lines']:
                        for span in line['spans']:
                            font = span['font']
                            print(Fore.YELLOW + f"Шрифт: {font}, Размер шрифта: {span['size']}")

    except Exception as e:
        print(Fore.RED + f"Ошибка при анализе объектов PDF: {e}")


def analyze_javascript(pdf_path):
    """
    Анализирует JavaScript, встроенный в PDF, с использованием функционала PeepDF.
    """
    try:
        print(Fore.CYAN + f"\nAnalyzing JavaScript in: {pdf_path}")
        pdf_parser = PDFParser()
        pdf_document = pdf_parser.parse(pdf_path, forceMode=True)
        js_analysis = analyzeJavaScript(pdf_document)

        if js_analysis:
            print(Fore.GREEN + "JavaScript найден и проанализирован.")
            print(Fore.YELLOW + js_analysis)
        else:
            print(Fore.YELLOW + "JavaScript не найден или нет подозрительного кода.")
    except Exception as e:
        print(Fore.RED + f"Ошибка при анализе JavaScript: {e}")


def check_pdf_signatures(pdf_path):
    """
    Проверка наличия и подлинности цифровых подписей в PDF-файле.
    """
    try:
        print(Fore.CYAN + f"\nChecking for digital signatures in: {pdf_path}")
        result = subprocess.run(['pdfsig', pdf_path], capture_output=True, text=True)
        if result.returncode == 0:
            print(Fore.GREEN + "Цифровые подписи документа:")
            print(Fore.YELLOW + result.stdout)
        else:
            print(Fore.RED + "Документ не содержит цифровых подписей или pdfsig не установлен.")
    except FileNotFoundError:
        print(Fore.RED + "Инструмент pdfsig не установлен или не найден в системном PATH.")
    except Exception as e:
        print(Fore.RED + f"Ошибка при проверке цифровых подписей: {e}")


def analyze_pdf_with_peepdf(pdf_path):
    """
    Дополнительный анализ PDF с помощью PeepDF для выявления вредоносных элементов и скрытых объектов.
    """
    try:
        print(Fore.CYAN + f"\nRunning PeepDF analysis on: {pdf_path}")
        pdf_parser = PDFParser()
        pdf_document = pdf_parser.parse(pdf_path, forceMode=True)
        if pdf_document:
            print(Fore.GREEN + "PeepDF: PDF successfully parsed and analyzed.")
            # Здесь можно добавить дополнительные проверки с использованием PDFCore, PDFCrypto и других модулей PeepDF
        else:
            print(Fore.RED + "PeepDF: Failed to parse PDF.")
    except Exception as e:
        print(Fore.RED + f"Ошибка при анализе PDF с PeepDF: {e}")


def process_pdf_file(pdf_path):
    """
    Выполняет полный анализ для одного PDF-файла.
    """
    print(Style.BRIGHT + Fore.MAGENTA + f"\n{'-' * 40}\nProcessing file: {pdf_path}\n{'-' * 40}")
    check_pdf_with_qpdf(pdf_path)
    analyze_metadata_with_pikepdf(pdf_path)
    analyze_binary_structure(pdf_path)
    analyze_pdf_objects(pdf_path)
    analyze_javascript(pdf_path)
    check_pdf_signatures(pdf_path)
    analyze_pdf_with_peepdf(pdf_path)
    print(Style.BRIGHT + Fore.MAGENTA + f"\n{'-' * 40}\nFinished processing: {pdf_path}\n{'-' * 40}\n")


def process_directory(directory_path):
    """
    Обрабатываетвсе PDF-файлы в указанном каталоге.
    """
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.lower().endswith('.pdf'):
                pdf_path = os.path.join(root, file)
                process_pdf_file(pdf_path)


if __name__ == "__main__":
    path = input(Style.BRIGHT + Fore.CYAN + "Please enter the path to your PDF file or directory: ")

    if os.path.isfile(path) and path.lower().endswith('.pdf'):
        # Если путь указывает на PDF-файл, обрабатываем его
        process_pdf_file(path)
    elif os.path.isdir(path):
        # Если путь указывает на каталог, обрабатываем все PDF-файлы в каталоге
        process_directory(path)
    else:
        print(Fore.RED + "The provided path is not a valid PDF file or directory.")

    print(Style.BRIGHT + Fore.GREEN + "\nAnalysis complete.")
