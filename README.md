# RedTeamTacticsEmulator
A powershell script to emulate some basic and advanced red team tactics for use in threat hunting

This script combines the basic and advanced techniques and randomly selects which set of tactics to use, then pauses for a random amount of time between 1 and 10 minutes before starting again.
Always ensure you have backups and understand each command before executing.
Only execute these scripts in controlled, isolated environments.
Obtain all necessary permissions before using tools like Mimikatz or executing potentially harmful scripts.
Be prepared for this script to run indefinitely until manually stopped, as there's a continuous loop (while ($true)) to keep running the tactics.
To safely stop the script, you can use Ctrl+C in the terminal where the script is running.
