import ctypes  
from ctypes import wintypes

*\# Описываем структуру MEMORY\_BASIC\_INFORMATION из Windows API*  
*\# Именно в неё ОС возвращает данные о состоянии страницы памяти*  
class MEMORY\_BASIC\_INFORMATION(ctypes.Structure):  
    \_fields\_ \= \[  
        ("BaseAddress", ctypes.c\_void\_p),  
        ("AllocationBase", ctypes.c\_void\_p),  
        ("AllocationProtect", wintypes.DWORD),  
        ("PartitionId", wintypes.WORD),  
        ("RegionSize", ctypes.c\_size\_t),  
        ("State", wintypes.DWORD),  
        ("Protect", wintypes.DWORD),  
        ("Type", wintypes.DWORD),  
    \]

*\# Словарь для расшифровки основных флагов защиты памяти*  
PROTECT\_FLAGS \= {  
    0x01: "PAGE\_NOACCESS (Доступ полностью запрещен)",  
    0x02: "PAGE\_READONLY (Только чтение)",  
    0x04: "PAGE\_READWRITE (Чтение и запись)",  
    0x20: "PAGE\_EXECUTE\_READ (Чтение и исполнение кода)",  
}

def analyze\_address(address):  
    mbi \= MEMORY\_BASIC\_INFORMATION()  
      
    *\# Вызываем функцию Windows API VirtualQuery для анализа адреса*  
    *\# Она обращается к подсистеме памяти ядра ОС*  
    result \= ctypes.windll.kernel32.VirtualQuery(  
        ctypes.c\_void\_p(address),  
        ctypes.byref(mbi),  
        ctypes.sizeof(mbi)  
    )  
      
    if result \== 0:  
        print("Ошибка вызова VirtualQuery")  
        return

    print(f"\\n--- Анализ виртуального адреса: {hex(address)} \---")  
    print(f"Базовый адрес региона: {hex(mbi.BaseAddress if mbi.BaseAddress else 0)}")  
    print(f"Размер региона страниц: {mbi.RegionSize} байт (примерно {mbi.RegionSize // 4096} страниц по 4КБ)")  
      
    *\# Расшифровываем текущий флаг защиты страницы*  
    current\_protect \= mbi.Protect  
    protect\_str \= PROTECT\_FLAGS.get(current\_protect, f"Другой флаг ({hex(current\_protect)})")  
    print(f"Текущая защита страницы (Protect): {protect\_str}")

*\# \--- ТЕСТ 1: Анализ обыкновенной переменной \---*  
print("Тест 1: Исследование памяти, где хранится строка Python")  
sample\_string \= "Тестовая строка для лабораторной работы"  
*\# Получаем виртуальный адрес объекта в памяти python*  
string\_address \= id(sample\_string)   
analyze\_address(string\_address)

*\# \--- ТЕСТ 2: Анализ нулевого адреса (nullptr) \---*  
print("\\nТест 2: Исследование нулевого адреса (NULL / nullptr)")  
analyze\_address(0)