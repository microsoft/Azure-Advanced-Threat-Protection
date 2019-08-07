# Introduction

Understanding Audit Policy configuration is imperative for your Domain Controllers.  This includes Azure Advanced Threat Protection (AATP) and Advanced Threat Analytics (ATA).  Use this tool to ensure your DCs have the proper settings to maximize your detection capability.

_**New features in recent versions:**_

- Ability to support Azure ATP (AATP); this is the default value now
- Ability to support ATA v1.9
- Ability to target a specific domain

## Getting Started

For explicit details on using this script, please refer [here](https://aka.ms/ataauditingblog).

For default values (assess against Azure ATP (AAT), throttling with 10 concurrent processes):

```PowerShell
    .\Measure-AatpDeployment.ps1
```

To configure the throttling of the processes (i.e. not being run on a DC or from a well resourced machine), use the "RunJobsThrottle" parameter.  In this example, we set this paramter to 100:

```PowerShell
    .\Measure-Aatpeployment.ps1 -RunJobsThrottle 100
```

To assess against ATA's v1.9, use the "AtaVersion" parameter, which takes a *string* value:

```PowerShell
    .\Measure-AatpDeployment.ps1 -AtaVersion "1.9"
```

This tool can assess ATA v1.9, 1.8 and 1.7.

To make the assessment against just one domain/child-domain, use the "Fqdn" parameter, as a *string* value:

```PowerShell
    .\Measure-AatpDeployment.ps1 -Fqdn "child.contoso.com"
```

## Getting Help

For help please refer to the above blog.  In addition, when getting help, please include the Transcript file as illustrated in the blog post.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
