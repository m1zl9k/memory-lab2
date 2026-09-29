import ctypes  
from ctypes import wintypes

*\# Константы флагов защиты Windows API*  
PAGE\_NOACCESS \= 0x01

*\# Создаем буфер в памяти и записываем туда число 500*  
my\_buffer \= ctypes.c\_long(500)  
buffer\_address \= ctypes.addressof(my\_buffer)

print(f"Буфер успешно создан по адресу: {hex(buffer\_address)}")  
print(f"Текущее значение в буфере: {my\_buffer.value}")

print("\\nОбращаемся к подсистеме памяти: принудительно устанавливаем флаг PAGE\_NOACCESS для этой страницы...")  
old\_protect \= wintypes.DWORD()

*\# Функция VirtualProtect меняет атрибуты страницы в таблице страниц процессора*  
success \= ctypes.windll.kernel32.VirtualProtect(  
    ctypes.c\_void\_p(buffer\_address),  
    ctypes.sizeof(my\_buffer),  
    PAGE\_NOACCESS,  
    ctypes.byref(old\_protect)  
)

if success:  
    print("Флаг защиты успешно изменен на PAGE\_NOACCESS\!")  
    print("Сейчас программа попытается прочитать данные по заблокированному адресу...")  
      
    *\# Попытка чтения. В этот момент MMU процессора зафиксирует нарушение правил,*   
    *\# аппаратно остановит выполнение и Windows уничтожит процесс.*  
    invalid\_read \= my\_buffer.value  
    print(f"Этот текст никогда не напечатается: {invalid\_read}")  
else:  
    print("Не удалось изменить флаги защиты.")