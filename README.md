import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import os
import re


# Function to analyze code and mark vulnerabilities
def analyze_code_for_security_vulnerabilities():
    file_path = file_path_var.get()
    if not file_path or not os.path.exists(file_path):
        messagebox.showwarning("File Error", "Please select a valid C code file first!")
        return

    vulnerabilities_found = []

    with open(file_path, 'r') as file:
        code = file.readlines()

    vulnerability_rules = [
        (r'\bstrcpy\b', "Usage of 'strcpy' without size check (potential buffer overflow)"),
        (r'\bgets\b', "Usage of 'gets' (inherently unsafe)"),
        (r'\bsprintf\b', "Usage of 'sprintf' without size check (potential buffer overflow)"),
        (r'\bstrcat\b', "Usage of 'strcat' without size check (potential buffer overflow)"),
        (r'\bscanf\s*\(.*[^&]\b', "Usage of 'scanf' without '&' in variable (potential buffer overflow)"),
        (r'\batoi\b', "Usage of 'atoi' without error handling (can cause issues)"),
        (r'\bfree\s*\(.*\b', "Incorrect use of 'free' (potential double free or memory leak)"),
        (r'\bmemcpy\b', "Usage of 'memcpy' without size validation (potential buffer overflow)"),
        (r'for\s*\(.*;.*;.*\)', "Improper loop bounds check (could lead to buffer overflows)"),
        (r'\bsystem\s*\(', "Usage of 'system' call (can lead to command injection)"),
    ]

    # Display the code and highlight vulnerabilities
    code_display.config(state=tk.NORMAL)
    code_display.delete("1.0", tk.END)
    for i, line in enumerate(code):
        code_display.insert(tk.END, line)

        for pattern, description in vulnerability_rules:
            if re.search(pattern, line):
                start_index = f"{i + 1}.0"
                end_index = f"{i + 1}.end"
                code_display.tag_add("highlight", start_index, end_index)
                vulnerabilities_found.append((i + 1, description))

    code_display.config(state=tk.DISABLED)

    output_display.config(state=tk.NORMAL)
    output_display.delete("1.0", tk.END)
    if vulnerabilities_found:
        output_display.insert(tk.END, "Detected Vulnerabilities:\n", "analysis_result")
        for line_num, description in vulnerabilities_found:
            output_display.insert(tk.END, f"Line {line_num}: {description}\n", "analysis_result")
    else:
        output_display.insert(tk.END, "No vulnerabilities detected based on predefined rules.\n", "analysis_result")
    output_display.config(state=tk.DISABLED)


# Function to handle file selection only
def upload_file():
    file_path = filedialog.askopenfilename(filetypes=[("C Files", "*.c")])
    if file_path and os.path.exists(file_path):
        file_path_var.set(file_path)  # Set the selected file path to the entry widget
        output_display.config(state=tk.NORMAL)
        output_display.insert(tk.END, "File selected. Now click 'Analyze' to scan for vulnerabilities.\n", "chatbot")
        output_display.config(state=tk.DISABLED)
    else:
        messagebox.showwarning("File Upload", "The selected file does not exist!")


# Function to display welcome messages sequentially
def display_welcome_messages():
    output_display.config(state=tk.NORMAL)
    window.after(2000, lambda: show_first_message())  # 2 seconds delay for the first message


def show_first_message():
    output_display.insert(tk.END, "Chatbot: Hello! Welcome to Secure Code Chatbot.\n", "chatbot")
    output_display.config(state=tk.DISABLED)
    window.after(3000, lambda: display_second_message())  # 3 seconds delay for the second message


def display_second_message():
    output_display.config(state=tk.NORMAL)
    output_display.insert(tk.END, "Chatbot: Please upload your C code file for analysis.\n", "chatbot")
    output_display.config(state=tk.DISABLED)


# Function to initiate a new conversation
def start_new_conversation():
    output_display.config(state=tk.NORMAL)
    output_display.delete("1.0", tk.END)
    output_display.config(state=tk.DISABLED)
    code_display.config(state=tk.NORMAL)
    code_display.delete("1.0", tk.END)
    code_display.config(state=tk.DISABLED)
    file_path_var.set("")  # Clear the file path
    display_welcome_messages()


# Tkinter GUI Setup
window = tk.Tk()
window.title("Secure Code Chatbot - Interactive C Code Analyzer")
window.geometry("1000x700")
window.configure(bg="#282C34")

# Chatbot conversation area
output_display_label = tk.Label(window, text="Chatbot Conversation:", font=("Helvetica", 14, "bold"), fg="white",
                                bg="#282C34")
output_display_label.grid(row=0, column=0, padx=20, pady=10, sticky="w")

output_display = scrolledtext.ScrolledText(window, width=90, height=10, state=tk.DISABLED, font=("Courier New", 12),
                                           bg="#1E1E1E", fg="#61AFEF")
output_display.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")
output_display.tag_config("chatbot", foreground="#98C379", font=("Helvetica", 12, "bold"))
output_display.tag_config("analysis_result", foreground="#E06C75", font=("Helvetica", 12))

# File selection section
file_select_frame = tk.Frame(window, bg="#282C34")
file_path_var = tk.StringVar()
file_path_label = tk.Label(file_select_frame, text="Selected File: ", font=("Helvetica", 12), bg="#282C34", fg="white")
file_path_label.pack(side=tk.LEFT, padx=5)
file_path_entry = tk.Entry(file_select_frame, textvariable=file_path_var, width=60, state='readonly',
                           font=("Helvetica", 12), bg="#1E1E1E", fg="#ABB2BF")
file_path_entry.pack(side=tk.LEFT, padx=5)
browse_button = tk.Button(file_select_frame, text="Browse", command=upload_file, font=("Helvetica", 12, "bold"),
                          bg="#98C379", fg="white")
browse_button.pack(side=tk.LEFT, padx=5)
file_select_frame.grid(row=2, column=0, padx=20, pady=10, sticky="w")

# Button frame
button_frame = tk.Frame(window, bg="#282C34")
analyze_button = tk.Button(button_frame, text="Analyze C Code", command=analyze_code_for_security_vulnerabilities,
                           font=("Helvetica", 12, "bold"), bg="#61AFEF", fg="white")
analyze_button.pack(side=tk.LEFT, padx=20)
new_conversation_button = tk.Button(button_frame, text="New Conversation", command=start_new_conversation,
                                    font=("Helvetica", 12, "bold"), bg="#E06C75", fg="white")
new_conversation_button.pack(side=tk.LEFT, padx=20)
button_frame.grid(row=3, column=0, padx=20, pady=10, sticky="w")

# C Code display area
code_display_label = tk.Label(window, text="Uploaded Code with Highlighted Vulnerabilities:",
                              font=("Helvetica", 14, "bold"), fg="white", bg="#282C34")
code_display_label.grid(row=4, column=0, padx=20, pady=10, sticky="w")
code_display = scrolledtext.ScrolledText(window, width=90, height=15, font=("Courier New", 12), bg="#1E1E1E",
                                         fg="white")
code_display.grid(row=5, column=0, padx=20, pady=10, sticky="nsew")
code_display.tag_config("highlight", background="red", foreground="white")

# Start the conversation flow with greeting
start_new_conversation()

window.mainloop()
