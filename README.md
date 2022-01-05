# agora-app
Agora helper app to download data and execute local tasks

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
