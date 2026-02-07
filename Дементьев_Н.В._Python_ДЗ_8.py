import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
import gzip
from io import BytesIO

# Функция для анализа перехваченных HTTP-запросов и ответов
def packet_callback(packet):
    # Обработка HTTP-запросов
    if packet.haslayer(HTTPRequest):
        http_request = packet[HTTPRequest]
        print(f"HTTP-запрос: {http_request.Method} {http_request.Host}{http_request.Path}")
        print(f"Заголовки запроса: {http_request.fields}")
        if http_request.Method == "POST":
            print(f"Тело запроса: {bytes(http_request.payload)}")
        # Поиск потенциальных точек XSS в параметрах запроса
        search_xss_in_payload(packet)
    # Обработка HTTP-ответов
    elif packet.haslayer(HTTPResponse):
        http_response = packet[HTTPResponse]
        print(f"HTTP-ответ: {http_response.StatusCode} {http_response.StatusLine}")
        print(f"Заголовки ответа: {http_response.fields}")
        if http_response.haslayer(scapy.Raw):
            body = http_response[scapy.Raw].load
            # Декомпрессия gzip-сжатых данных, если они есть
            if b"gzip" in http_response.fields.get("Content-Encoding", "").lower():
                body = decompress_gzip(body)
            print(f"Тело ответа: {body}")
            # Поиск XSS в теле ответа
            search_xss_in_response(body)

# Функция для поиска XSS в полезной нагрузке (полях запроса или ответах)
def search_xss_in_payload(packet):
    # Ищем потенциальные XSS-полезные нагрузки в URL или теле запроса
    url = packet[HTTPRequest].Host + packet[HTTPRequest].Path
    payload = bytes(packet[HTTPRequest].payload).decode(errors="ignore")
    
    # Примеры полезных нагрузок XSS
    xss_payloads = ["<script>alert('XSS')</script>", "<img src='nonexistent.jpg' onerror='alert(\"XSS\")'>"]
    for xss in xss_payloads:
        if xss in url or xss in payload:
            print(f"Обнаружен потенциальный XSS в запросе: {xss}")

# Функция для поиска XSS в теле ответа
def search_xss_in_response(body):
    # Примеры полезных нагрузок XSS
    xss_payloads = ["<script>alert('XSS')</script>", "<img src='nonexistent.jpg' onerror='alert(\"XSS\")'>"]
    for xss in xss_payloads:
        if xss.encode() in body:
            print(f"Обнаружен XSS в ответе: {xss}")

# Функция для распаковки gzip сжатых данных
def decompress_gzip(data):
    buf = BytesIO(data)
    f = gzip.GzipFile(fileobj=buf)
    return f.read()

# Сохранение перехваченных пакетов в файл .pcap
def save_traffic_to_pcap(packets, filename="captured_traffic.pcap"):
    scapy.wrpcap(filename, packets)
    print(f"Трафик сохранен в файл: {filename}")

# Основная функция для захвата и анализа трафика
def sniff_traffic():
    print("Начинаю перехват трафика HTTP...")
    packets = scapy.sniff(filter="tcp port 80", prn=packet_callback, store=1, count=100)
    # Сохраняем захваченные пакеты в файл .pcap
    save_traffic_to_pcap(packets)
    
    # Возвращаем перехваченные пакеты для дальнейшего анализа
    return packets

# Запуск анализа
if __name__ == "__main__":
    sniff_traffic()
