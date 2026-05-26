I created a vault_sweep.sh script which performs threat detection in shell script files (.sh), detects hardcoded secrets in .py and .js files, and sanitizes .env files.I made the script executable in the format:./vault_sweep.sh <testrepo>
At the beginning of the script, I used an if condition to check whether the target directory argument was entered correctly. If not, the script exits with status code 1, indicating failure.
After that, I recursively traversed all files in the target directory using the find command. I piped the output into a while loop to iteratively process each file. Using if conditions, I identified the type of file currently being scanned and applied the corresponding checks required by the task.

#LOG FILES:
I created a dedicated logs directory and restricted its permissions so that only the owner can access it. Similarly, the log file was given read and write permissions only for the owner using the chmod command.
I also created a custom log_msg() function to append logs into the log file along with:timestamplog, type (INFO, WARN, FIX, SKIP) and corresponding log message
This was done according to the logging format specified in the task.

#THREAT DETECTION IN .sh FILES
The script scans shell scripts for multiple dangerous patterns, including the ones mentioned in the task as well as a few additional patterns.
Patterns Detected
mkfs and dd if - These commands can format or overwrite disks and partitions, potentially destroying data.
shutdown and reboot - These commands can stop or restart the system unexpectedly, disrupting services.
curl and wget regex patterns - These can download remote scripts or malicious payloads and directly pipe them into sh or bash for execution.
/dev/tcp/ - This can be used to create raw TCP connections and is commonly seen in reverse shell payloads.
rm -rf / - This command can recursively delete the entire filesystem.
sudo su - This can provide elevated privileges and may be abused by attackers.
chmod 777 - This gives unnecessary read, write, and execute permissions to everyone.
scp - This can transfer files outside the system, including potentially sensitive data.

The script first checks whether a shell script is world-writable, meaning writable by anyone on the system. Such files can be modified by attackers.
If detected: A warning is logged. The user is interactively asked whether the permissions should be fixed.If the user agrees, the script removes world-write permissions and logs the remediation action as well.
After permission checks, the script iterates through all dangerous patterns using a for loop and checks the currently scanned file using grep.


#BONUS TASK 1 - SECRET DETECTION IN .py AND .js FILES
For .py and .js files, I scanned for suspicious secret patterns such as:API keys, tokens and secret strings.
These could potentially grant unauthorized access to services if exposed publicly.
The script scans these files using regex patterns and reports the matching lines along with line numbers.

#SANITIZING .env FILES
The script creates a separate sanitized version of every .env file.
It validates each environment variable line using regex matching with =~ and rejects:invalid variable name formats, spaces around =, unnecessary quotes and other malformed entries.
The regex validation also rejects patterns like export PATH=....
Additionally, the script checks for sensitive variable names such as: PASSWORD, PATH, TOKEN, SECRET and rejects them from the sanitized output.
Only valid and safe environment variables are written into the .env.sanitized file.

#PROBLEMS FACED
I'm a complete beginner to bash scripting, so I'd the initial hurdles of missing space which pops error during parsisng along with these:
Initially, I used read file instead of read -r file, which caused issues while processing filenames containing backslashes (\).
At first, I used the ls command to list files and pipe them into a while loop. However, this approach could not recursively traverse subdirectories or detect hidden files properly. I later switched to using the find command, which solved the issue.
I also faced multiple Bash syntax issues involving missing fi and done statements while working with nested loops and conditions.
Another issue occurred when using read inside a piped while loop. The script was consuming pipeline input instead of taking user input interactively. This was fixed using /dev/tty.




