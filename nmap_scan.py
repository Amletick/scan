import nmap


def nmap_scan(host):
    nm = nmap.PortScanner()
    nm.scan(host, arguments='-sV -Pn -T4')  # Опции для сканирования

    with open('nmap_scan_results.txt', 'w') as file:
        for host in nm.all_hosts():
            file.write(f"Хост : {host}\n")
            file.write(f"Статус : {nm[host].state()}\n")

            for proto in nm[host].all_protocols():
                file.write(f"Протокол : {proto}\n")

                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]['name']
                    file.write(f"Порт : {port}\t Статус : {nm[host][proto][port]['state']}\t Сервис : {service}\n")


if __name__ == '__main__':
    host = input("Введите целевого хоста: ")
    nmap_scan(host)
    print("Скан завершён. Результаты сохранены в nmap_scan_results.txt")