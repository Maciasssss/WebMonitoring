import threading
from scapy.all import get_if_list, get_working_ifaces
from web import create_app

def main():
    app = create_app()

    app.run(host='0.0.0.0', port=8080, debug=True)

if __name__ == "__main__":
    main()
