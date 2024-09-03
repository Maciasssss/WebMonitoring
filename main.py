import threading
from scapy.all import get_if_list, get_working_ifaces
from web import create_app

def main():
    # Tworzenie aplikacji Flask
    app = create_app()

    # Uruchomienie serwera Flask w głównym wątku
    app.run(host='0.0.0.0', port=8080, debug=True)

if __name__ == "__main__":
    main()
