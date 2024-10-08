# 🕵️‍♂️ WebSniffer Dashboard: Packet Sniffing and Network Monitoring Application

## 📖 Overview
This project is part of my **engineering thesis** in **Computer Science**. The aim is to develop a comprehensive **packet sniffing and network monitoring application** that provides real-time analysis, traffic insights, and security threat detection.

The app features an **interactive dashboard** that displays various metrics such as traffic statistics, packet details, and potential security threats (like **DDoS**, **brute force attacks**, etc.). It offers an intuitive interface that network administrators and security professionals can use to monitor and protect their networks.

---

## 🚀 Features
- **Real-time Packet Capture**: Monitor and capture network packets passing through interfaces in real-time.
- **Detailed Traffic Analysis**: Gain insights into traffic patterns, detect potential bottlenecks, and visualize the data through charts.
- **Customizable Filters**: Apply filters to focus on specific protocols, IPs, or ports.
- **Security Threat Detection**: Detect and notify users of suspicious activities such as DDoS attacks, brute force login attempts, and more.
- **Interactive Dashboard**: View network metrics via an easy-to-use, mobile-responsive dashboard.
- **Data Export**: Export captured data for offline analysis or reporting.

---

## 🛠️ Technologies Used
| **Technology**        | **Description**                                              |
|-----------------------|--------------------------------------------------------------|
| **Frontend**          | HTML, CSS (Grid, Flexbox), JavaScript (jQuery, Chart.js), Bootstrap |
| **Backend**           | Python (Flask)                                               |
| **Packet Sniffing**   | Scapy                                                        |
| **Data Management**   | SQLite                                                       |
| **Real-time**         | WebSockets (Flask-SocketIO)                                  |
| **Security Detection**| Custom-built algorithms for detecting common network attacks |

---

## 🖼️ **Application Screenshots**

### Main Page
<img src="assets/images/MainPage.png" alt="Main Page" width="700">

### Key Features
<img src="assets/images/KeyFeatures.png" alt="Key Features" width="700">

### How It Works Section
<img src="assets/images/HowitWorks.png" alt="How It Works" width="700">

### Live Packet Captures
<img src="assets/images/LivePacketCaptures.png" alt="Live Packet Captures" width="700">

### Flow Statistics
<img src="assets/images/FlowStats.png" alt="Flow Statistics" width="700">

### Stats and Alerts Section
<img src="assets/images/StatsandAlertSection.png" alt="Stats and Alerts" width="700">

### Alert Modal
<img src="assets/images/Alertmodal.png" alt="Alert Modal" width="700">

### Settings
<img src="assets/images/Settings.png" alt="Settings" width="700">

## 📚 How It Works
1. **Select Network Interface**: Choose the network interface you want to monitor.
2. **Set Custom Filters**: Focus on specific network traffic using customizable filters (protocols, IP addresses, ports).
3. **Monitor Traffic**: Real-time visualization of packet details (source/destination IP, protocols, etc.).
4. **Detect and Alert**: Get alerts when potential threats like DDoS, port scans, or brute force attempts are detected.
5. **Export Data**: Save traffic data for offline analysis.

---

## 🖥️ Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/WebSnifferDashboard.git
    cd WebSnifferDashboard
    ```

2. Install required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Start the application:
    ```bash
    flask run
    ```

4. Access the application in your browser at `http://127.0.0.1:5000`.

---

## 🛡️ Security Detection Algorithms
The application includes the following threat detection modules:

- **DDoS Attack Detection**
- **Brute Force Login Detection**
- **DNS Tunneling**
- **Port Scanning**
- **SYN Flood**
- **Spoofing**
- **Password Exfiltration**

Each detector utilizes a combination of real-time traffic analysis and machine learning to provide accurate threat identification.

