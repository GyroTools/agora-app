# agora-app
Agora helper app to download data and execute local tasks

## Download
The agora-app can be downloaded from the [GyroTools Github](https://github.com/GyroTools/agora-app/releases). Please make sure you choose the correct platform.

## Installation

### Windows
1. Create a folder somewhere in your system, ex.: C:\agora-app.
2. Download the binary and put it into the folder you created. The following assumes that the binary is called agora-app.exe
3. Run an [elevated command prompt](https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/starting-windows-powershell?view=powershell-7#with-administrative-privileges-run-as-administrator)
4. Register the agora-app:
    ```
    .\agora-app register
    ```
   During the registering process you have to enter the download path, Agora URL and credentials. 
5. Install the agora-app as a service and start it. You can either run the service using the Built-in System Account (recommended) or using a user account.

    Run service using Built-in System Account (under directory created in step 1. from above, ex.: C:\agora-app)

    ```
    cd C:\agora-app
    .\agora-app.exe install
    .\agora-app.exe start
    ```

    Run service using user account (under directory created in step 1. from above, ex.: C:\agora-app)
    You have to enter a valid password for the current user account, because it’s required to start the service by Windows:

    ```
    cd C:\agora-app
    .\agora-app.exe install --user ENTER-YOUR-USERNAME --password ENTER-YOUR-PASSWORD
    .\agora-app.exe start
    ```

### Linux
#### Run as service (Recommended)
Running the agora-app as service is the recommended way, but needs root privileges. If you don't have administrator privileges please go to the next section in order to [run the app as local user](#Run-as-local-user).

1. Download the binary into a folder of your choice
2. Change to the download directory and copy the binary to `/usr/local/bin/`:
     ```
     sudo cp ./agora-app /usr/local/bin/
     ```
3. Give it permissions to execute:
     ```
     sudo chmod +x /usr/local/bin/agora-app
     ```
4. Register the agora-app:
     ```
     sudo agora-app register
     ```
5. Install and run as service:
     ```
     sudo agora-app install --user=$USER --working-directory=$HOME
     sudo agora-app start
     ```

#### Run as local user
1. Download the binary into a folder of your choice and change into it
2. Give it permissions to execute:
     ```
     chmod +x ./agora-app
     ```
3. Register the agora-app:
     ```
     ./agora-app register
     ```
4. Run the app:
     ```
     ./agora-app run
     ```