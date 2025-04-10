How to Use These

    ARM Templates:
        Save as template.json.
        Deploy with: az deployment group create --resource-group myResourceGroup --template-file template.json.
        For Example 3, pass the shared key: --parameters sharedKey=MySecretKey123.
    Azure CLI:
        Run commands in sequence in a terminal with Azure CLI installed and logged in (az login).
        Replace myResourceGroup with your resource group name.
    Customization:
        Update regions (e.g., westus), IP ranges, or names as needed.
        For VPN, replace 203.0.113.1 with your actual on-premises VPN device’s public IP.

