import tkinter as tk
from tkinter import scrolledtext
import time
import random

# Constants for energy calculation
TRANSMISSION_POWER = 0.5  # Power in watts

# Function to insert log with specified color and double spacing
def insert_log(log, message, tag):
    log.insert(tk.END, message + "\n\n", tag)  # Double spacing
    log.yview(tk.END)  # Scroll to the end of the log

# Function to simulate clock synchronization
def synchronize_clock(sender_log, receiver_log):
    current_time = time.strftime('%H:%M:%S')  # Get current time
    insert_log(sender_log, f"Synchronizing clock to: {current_time}", "info")
    insert_log(receiver_log, f"Synchronizing clock to: {current_time}", "info")
    time.sleep(1)  # Simulate delay
    insert_log(sender_log, "Clock synchronized successfully.", "success")
    insert_log(receiver_log, "Clock synchronized successfully.", "success")

# Function to simulate packetization
def packetize_data(plain_text, sender_log, receiver_log):
    packet_size = 128  # Fixed packet size in bytes
    packets = [plain_text[i:i + packet_size] for i in range(0, len(plain_text), packet_size)]
    num_packets = len(packets)
    insert_log(sender_log, f"Packetizing data... {num_packets} packets created.", "info")
    insert_log(receiver_log, f"Packetizing data... {num_packets} packets expected.", "info")
    time.sleep(1)  # Simulate delay
    return packets, num_packets

# AES-like encryption and decryption without external libraries
def aes_encrypt_decrypt(data):
    key = 'secretkey1234567'  # 16-character key (example)
    transformed = ''.join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data)])
    return transformed

# Function to simulate encryption (AES-like reversible operation)
def encrypt_packet(packet, sender_log):
    encrypted_packet = aes_encrypt_decrypt(packet)  # AES-like encryption
    insert_log(sender_log, f"Encrypted packet: {encrypted_packet}", "data")
    return encrypted_packet

# Function to simulate sending a packet with dynamic channel hopping
def send_packet(packet, current_channel, sender_log, receiver_log):
    insert_log(sender_log, f"Sending packet over channel {current_channel}", "info")
    insert_log(receiver_log, f"Waiting for packet on channel {current_channel}", "info")
    time.sleep(1)  # Simulate transmission delay
    packet_lost = random.random() < 0.1  # Simulate 10% chance of packet loss
    return not packet_lost

# Function to simulate dynamic channel hopping for secure communication
def dynamic_channel_hopping(current_channel):
    return (current_channel + random.randint(1, 5)) % 125 + 108  # Simulate hopping in ISM band

# Function to calculate and display latency, throughput, and energy consumption
def calculate_metrics(start_time, num_packets, total_packet_loss, total_transmission_time):
    latency = (time.time() - start_time) / num_packets  # Average latency per packet
    throughput = (num_packets - total_packet_loss) / (time.time() - start_time)  # Packets per second
    energy_consumption = TRANSMISSION_POWER * total_transmission_time  # Energy = power * time
    return latency, throughput, energy_consumption

# Function to simulate different types of attacks
def simulate_attack():
    attack_type = random.choice(['none', 'jamming', 'mitm', 'replay', 'packet_loss'])  # Random attack type
    return attack_type

# Function to handle retransmission on attack detection
def handle_retransmission(packet, current_channel, sender_log, receiver_log):
    attack_type = simulate_attack()
    
    if attack_type == 'none':
        return True  # No attack detected, transmission successful
    elif attack_type == 'jamming':
        insert_log(sender_log, "Jamming attack detected. Resending packet on a different channel...", "warning")
        insert_log(receiver_log, "Jamming attack detected. Awaiting retransmission...", "warning")
    elif attack_type == 'mitm':
        insert_log(sender_log, "MITM attack detected. Resending packet on a secure channel...", "warning")
        insert_log(receiver_log, "MITM attack detected. Awaiting retransmission...", "warning")
    elif attack_type == 'replay':
        insert_log(sender_log, "Replay attack detected. Resending packet with updated encryption...", "warning")
        insert_log(receiver_log, "Replay attack detected. Awaiting retransmission...", "warning")
    elif attack_type == 'packet_loss':
        insert_log(sender_log, "Packet lost. Resending packet...", "warning")
        insert_log(receiver_log, "Packet lost. Awaiting retransmission...", "warning")

    # Retransmit by changing channel or updating encryption
    current_channel = dynamic_channel_hopping(current_channel)
    return False, current_channel  # Indicate retransmission required and new channel

# Function to simulate the entire MCSC transmission process
def start_transmission():
    sender_log.delete(1.0, tk.END)  # Clear log at the start
    receiver_log.delete(1.0, tk.END)  # Clear log at the start
    metrics_log_sender.delete(1.0, tk.END)  # Clear metrics log at the start
    metrics_log_receiver.delete(1.0, tk.END)  # Clear metrics log at the start

    plain_text = sender_input.get(1.0, tk.END).strip()  # Get plain text input from the user
    if not plain_text:
        insert_log(sender_log, "No plain text entered!", "warning")
        return

    # Display plain text message
    insert_log(sender_log, f"Plain text message: {plain_text}", "info")

    # Synchronize clock
    synchronize_clock(sender_log, receiver_log)

    # Calculate and display total data size
    total_data_size = len(plain_text.encode('utf-8'))  # Total size in bytes
    insert_log(sender_log, f"Total data size (plain text): {total_data_size} bytes", "info")

    # Packetize data
    packets, num_packets = packetize_data(plain_text, sender_log, receiver_log)
    insert_log(sender_log, f"Total number of packets: {num_packets}", "info")
    insert_log(receiver_log, f"Total number of packets expected: {num_packets}", "info")

    # Start sending packets using MCSC framework (multi-channel hopping)
    current_channel = 108  # Initial ISM channel
    total_packet_loss = 0  # Initialize packet loss count
    total_transmission_time = 0  # Total time spent in transmission (for energy calculation)
    start_time = time.time()  # Start time for calculating latency

    for i, packet in enumerate(packets):
        encrypted_packet = encrypt_packet(packet, sender_log)  # Encrypt packet

        # Send and handle retransmission in case of attack detection
        successful_receive = False
        while not successful_receive:
            attack_result = handle_retransmission(encrypted_packet, current_channel, sender_log, receiver_log)

            if attack_result is True:
                start_packet_time = time.time()  # Track time for transmission
                success = send_packet(encrypted_packet, current_channel, sender_log, receiver_log)
                transmission_time = time.time() - start_packet_time  # Calculate transmission time for this packet
                total_transmission_time += transmission_time  # Add to total transmission time

                if not success:
                    insert_log(sender_log, "Packet lost. Retrying...", "warning")
                    insert_log(receiver_log, "Packet lost. Awaiting retransmission...", "warning")
                    total_packet_loss += 1  # Count packet loss
                    continue  # Retry sending the same packet

                # If no attack is detected, mark as successfully received
                successful_receive = True

                # Decrypt packet at the receiver side for simulation
                decrypted_packet = aes_encrypt_decrypt(encrypted_packet)  # AES-like decryption
                insert_log(receiver_log, f"Encrypted packet: {encrypted_packet}", "data")
                insert_log(receiver_log, f"Decrypted packet: {decrypted_packet}", "data")

            else:
                current_channel = attack_result[1]  # Get new channel for retransmission
                insert_log(sender_log, f"Changing to channel {current_channel} for retransmission.", "info")

    insert_log(sender_log, "All packets transmitted successfully.", "success")
    insert_log(receiver_log, "All packets received successfully.", "success")

    # Calculate metrics
    latency, throughput, energy_consumption = calculate_metrics(start_time, num_packets, total_packet_loss, total_transmission_time)

    # Display metrics in logs
    metrics_log_sender.insert(tk.END, f"Packet Delivery Ratio (PDR): {(num_packets - total_packet_loss) / num_packets * 100:.2f}%\n")
    metrics_log_sender.insert(tk.END, f"Average Latency: {latency:.4f} seconds per packet\n")
    metrics_log_sender.insert(tk.END, f"Throughput: {throughput:.2f} packets/second\n")
    metrics_log_sender.insert(tk.END, f"Total Energy Consumption: {energy_consumption:.4f} joules\n")

    metrics_log_receiver.insert(tk.END, f"Packet Delivery Ratio (PDR): {(num_packets - total_packet_loss) / num_packets * 100:.2f}%\n")
    metrics_log_receiver.insert(tk.END, f"Average Latency: {latency:.4f} seconds per packet\n")
    metrics_log_receiver.insert(tk.END, f"Throughput: {throughput:.2f} packets/second\n")
    metrics_log_receiver.insert(tk.END, f"Total Energy Consumption: {energy_consumption:.4f} joules\n")

# Create main sender window (MCSC: Sender)
sender_window = tk.Tk()
sender_window.title("MCSC: Sender")
sender_window.geometry("600x800")
sender_window.configure(bg="#f0f8ff")  # Light blue background

# Sender widgets
sender_label = tk.Label(sender_window, text="Sender", font=("Arial", 16), bg="#f0f8ff", fg="#333")
sender_label.pack(pady=10)

sender_input = scrolledtext.ScrolledText(sender_window, width=70, height=5, wrap=tk.WORD, font=("Arial", 12), bg="#ffffff", fg="#000000")
sender_input.pack(pady=5)

start_button = tk.Button(sender_window, text="Start Transmission", command=start_transmission, font=("Arial", 12, "bold"), bg="#add8e6", fg="black")
start_button.pack(pady=10)

sender_log_label = tk.Label(sender_window, text="Sender Logs:", font=("Arial", 14), bg="#f0f8ff", fg="#333")
sender_log_label.pack(pady=5)

sender_log = scrolledtext.ScrolledText(sender_window, width=70, height=20, wrap=tk.WORD, font=("Arial", 11), bg="#ffffff", fg="#000000")
sender_log.pack(pady=5)

# Metrics Logs
metrics_log_label = tk.Label(sender_window, text="Metrics Logs:", font=("Arial", 14), bg="#f0f8ff", fg="#333")
metrics_log_label.pack(pady=5)

metrics_log_sender = scrolledtext.ScrolledText(sender_window, width=70, height=10, wrap=tk.WORD, font=("Arial", 11), bg="#ffffff", fg="#000000")
metrics_log_sender.pack(pady=5)

# Tag configurations for colors in logs (Sender)
sender_log.tag_config("info", foreground="blue")
sender_log.tag_config("warning", foreground="red")
sender_log.tag_config("success", foreground="green")
sender_log.tag_config("data", foreground="purple")

# Set up the main receiver window (MCSC: Receiver)
receiver_window = tk.Tk()
receiver_window.title("MCSC: Receiver")
receiver_window.geometry("600x800")
receiver_window.configure(bg="#f0f8ff")  # Light blue background

# Receiver widgets
receiver_log_label = tk.Label(receiver_window, text="Receiver Logs:", font=("Arial", 14), bg="#f0f8ff", fg="#333")
receiver_log_label.pack(pady=5)

receiver_log = scrolledtext.ScrolledText(receiver_window, width=70, height=20, wrap=tk.WORD, font=("Arial", 11), bg="#ffffff", fg="#000000")
receiver_log.pack(pady=5)

# Metrics Logs
receiver_metrics_log_label = tk.Label(receiver_window, text="Metrics Logs:", font=("Arial", 14), bg="#f0f8ff", fg="#333")
receiver_metrics_log_label.pack(pady=5)

metrics_log_receiver = scrolledtext.ScrolledText(receiver_window, width=70, height=10, wrap=tk.WORD, font=("Arial", 11), bg="#ffffff", fg="#000000")
metrics_log_receiver.pack(pady=5)

# Tag configurations for colors in logs (Receiver)
receiver_log.tag_config("info", foreground="blue")
receiver_log.tag_config("warning", foreground="red")
receiver_log.tag_config("success", foreground="green")
receiver_log.tag_config("data", foreground="purple")

# Start the Tkinter event loop
sender_window.mainloop()
receiver_window.mainloop()
