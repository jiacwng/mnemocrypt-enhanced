## About the tool
<em>Mnemocrypt</em> is a random forest classifier based tool for detection and partial identification of cryptographic functions in x86 executables. The machine learning model bases its predictions on general metrics related to the structure of functions, as well as on statistics on metrics related to their content with different levels of granularity, the building blocks of which are essentially mnemonics of assembly instructions. Mnemocrypt can be considered as a kind of generalisation of Caballero heuristics based approaches and incorporates some of them. Mnemocrypt IDA plugin can provide partial cryptographic identification information if combined with a slightly modified version of Findcrypt3 (included in this repository), which is an IDA plugin for cryptography detection and identification, based on yara rules. The tool has been tested on IDA Pro 8.3 and 9.0, both with Python 3.9.2, under Windows environment with WSL.

## Repository vs release
The primary role of the repository is to serve as support to the research paper <em>Mnemocrypt: A Machine Learning Approach for Cryptographic Function Detection in x86 Executables</em>, while the release version contains a directly ready to use version of the plugin.

## Example of output of Mnemocrypt plugin in IDA GUI
![image info](mnemocrypt.png)

- Coloring convention:
  - yellow: confidence score 0.5-0.75
  - orange: confidence score 0.75-0.95
  - red: confidence score 0.95-1.0

- Minimal confidence score and coloring convention can be changed in the plugin script <em>mnemocrypt.py</em>

- Higher the confidence score is and more likely, according to Mnemocrypt, a given function is to perform cryptographic operations.

- Most frequent kinds of false postiives with high confidence score (greater than 0.9): compression or encoding related functions as well as functions performing some complex, not cryptography related, computations or data processing.

## How to install and use Mnemocrypt IDA Pro plugin

#### What to do just after having downloaded the repository to quickly test Mnemocrypt on the provided malware dataset
1. If the user has IDA under Linux environment or under Windows environment and have WSL, then run `./prepare_environment.sh` and answer to the prompts. This should automatically initialize some essential veriables in scripts to run later.
2. If the user is dealing with some other environment or if <em>./prepare\environment.sh</em> is not working, then he/she has to set <strong>idat\_path</strong> variable, with absolute path to idat.exe, in <em>./common/building\_wrapper.sh</em> and <em>./tool/plugin\_batch.sh</em>, and set <strong>repository\_dirpath</strong> variable in <em>findcrypt3.py</em> with <em>mnemocrypt.py</em>, which is the path to the location of this repository; finally, the user has to move the files from <em>move\_to\_ida\_plugins/</em> to IDA plugins directory (C:\\Users\\john\\Programs\\IDA\_Pro\_9.0\\plugins for example).
3. <strong>Disable antivirus</strong>, because it can interfere with IDA databases generation; the antivirus can be reactivated after the end of generation of IDA database files of executables from the malware dataset.
4. Install necessary Python modules by running `pip install -r requirements.txt` (Python 3.9.2 recommended).
5. Run `./quick_start.sh`; expect the process to take several hours (e.g. 2 hours on architecture with 2.7GHz, 16GB RAM and 250GB SSD under Windows environment).
6. Use Mnemocrypt in IDA GUI (by opening IDA database files of provided malware samples) at your wish (shortcut Ctrl-Shift-M; name of the plugin in IDA GUI: Mnemocrypt) or run Mnemocrypt in batch mode for all analyzed binaries with `./tool/plugin\_batch.sh mnemocrypt` and access exported results in <em>./tool/mnemocrypt\_results.csv</em>.

#### How to use the provided pre-trained Mnemocrypt model to classify functions from your set of binaries
1. Perform the steps 1, 2, 3 and 4 from the previous section, unless already done.
2. Ensure that pre-trained Mnemocrypt model <em>trained\_mnemocrypt.pkl</em> is present in <em>./common/</em> folder (unzip <em>./data.zip</em> with provided password, if necessary).
3. If <em>./tool/raw\_executables/</em>, <em>./tool/ida\_databases/</em> or <em>./tool/computed\_features/</em> already exist then remove them, by making backups of them and of previously generated files (<em>./tool/immediate\_crypto\_functions.json</em>, <em>./tool/immediate\_non\_crypto\_functions.json</em>, <em>./tool/unrecognized\_mnemonics.json</em>, <em>./tool/findcrypt\_matches.csv</em>, <em>./tool/findcrypt\_tags.json</em> and <em>./tool/mnemocrypt\_predictions.csv</em>), if necessary.
4. Place the raw binaries from your set to <em>./tool/raw\_executables/</em>.
5. Run `./common/building\_wrapper.sh databases && ./common/building\_wrapper.sh features && ./tool/plugin\_batch.sh findcrypt`
6. See step 6 from the section above.

#### Important notes
- In this README, "./" stands for the root directory of the repository
- The zip archive <em>./data.zip</em> (stored in the repo via git LFS) with executables and trained model is protected by password (hardcoded in <em>quick\_start.sh</em>)
- The pre-trained model corresponds to the default training, and the user can customize it by modifying hyperparameters in <em>./training/train\_mnemocrypt.py</em> or features in <em>./common/internal\_compute\_features.py</em>, or any data used to generate features.
- The zip archive contains malware samples, so, in case the user wants to run Mnemocrypt on them, it is recommended to work in isolated sandbox environment and it is mandatory to deactivate antivirus at least until all IDA databases of malware samples have been generated
- Mnemocrypt can't be used on a binary (its IDA database in practice) unless its corresponding .csv file with computed features is present in <em>computed\_features</em>
- <strong>Relation between Mnemocrypt and Findcrypt IDA plugins</strong>: Mnemocrypt is fully independant from Findcrypt in its approach to address the problem of cryptography detection, so it can be run without even having Findcrypt plugin installed. However, the cryptographic byte patterns matched by rules in Findcrypt allow to visualize more cryptographic identification information than with Mnemocrypt alone (natively supporting only AES-NI and Intel SHA extensions at the moment).

## Repository structure
 ```C
mnemocrypt/
├─ common/                                 // Regroups files related to both tool and training modes
│  ├─ building_wrapper.sh                  // Generic script to either create IDA databases from raw executables or run features computation for already built IDA databases
|  ├─ categories.json                      // Categories of mnemonics and their associated roots
|  ├─ internal_compute_features.py         // Features computation
|  ├─ prepare_roots.py                     // Combines information from categories.json and root_prefixes.json to build prepared_roots.json
|  ├─ prepared_roots.json                  // Used in internal_compute_features.py for time efficient mnemonics-roots matching 
|  ├─ root_prefixes.json                   // Mnemonics prefixes appended to roots for mnemonics matching during features computation
|  ├─ training_set_basenames_listing.txt   // Regroups the basenames (i.e. filenames without extensions) of the executables belongining to the training set
|
├─ data.zip                                // Initially large files are stored in zip format in order to minimize the size of the repository; the zip contains OpenSSL and Libsodium cryptographic libraries built with different configurations (training set), some real-world malware samples and pre-trained Mnemocrypt model
|
├─ doc/                                    // Additional explanatory information
│  ├─ crypto_functions_labels.txt          // Convention on the cryptographic labels from files in crypto_functions_names/ directory
│  ├─ malware_samples_name_mapping.json    // Stores information on original names of provided malware samples, given by their hashes
│  ├─ merged_roots.txt                     // Indicates what some mnemonics roots, statistics on which are present among features, actually correspond to
│  ├─ prefixes_documentation.txt           // Origine of each root prefix 
│  ├─ roots_documentation.txt              // Explanation of semantics behind each declared mnemonics root
|
├─ LICENSE
├─ mnemocrypt.png
|
├─ move_to_ida_plugins/                    // Files from this directory are to be moved to the directory plugins/ of IDA
│  ├─ findcrypt3.py                        // Slightly modified version of Findcrypt3 (add to output Xrefs to functions matching crypto-signatures by their code or referencing data matching crypto-signatures)
│  ├─ findcrypt3.rules                     // Updated rules (crypto-signatures) used by Findcrypt (merge between yara rules from original repository https://github.com/polymorf/findcrypt-yara and the ones from https://github.com/packmad/findcrypt-PYara)
│  ├─ mnemocrypt.py                        // Mnemocrypt plugin
|
├─ quick_start.sh                          // Unzip data, build IDA databases of binaries from the provided malware dataset, compute their features, run Findcrypt and then Mnemocrypt on them in batch mode with export of results
├─ requirements.txt                        // Using Python 3.9.2 is highly recommended!
├─ README.md
|
├─ tool/                                   // Regroups information related to the binaries to use Mnemocrypt with (dataset of real world malware samples provided as example) and Mnemocrypt and modified Findcrypt plugins-related scripts
|  ├─ internal_findcrypt_batch.py          // Automatically run modified Findcrypt plugin on given binary and exports results
|  ├─ internal_mnemocrypt_batch.py         // Automatically run Mnemocrypt plugin on given and exports results 
|  ├─ plugin_batch.sh                      // Generic script allowing to run either modified Findcrypt or Mnemocrypt plugins on all binaries under study (based on the content of computed_features/) with results export
|
├─ training/                               // Includes information on the training set and model training script
|  ├─ crypto_functions_names/              // Regroups functions from the training set labeled as cryptographic (achieved by manual labelling process); the training process is heavliy based on this information
│  ├─ train_mnemocrypt.py                  // Train the random forest classifier of Mnemocrypt basing on features from computed_features/ directory; script not to be run unless the user wants to customize Mnemocrypt
```

#### Generated or extracted files and directories
- <em>./[training|tool]/computed\_features/</em>:    Contains computed features (in form of .csv files associated to each binaries)
- <em>./tool/findcrypt\_matches.csv</em>:                   Results of Findcrypt run on all the executables from <em>./tool/</em> directory
- <em>./tool/findcrypt\_tags.json</em>:                     Part of information from <em>./tool/findcrypt\_matches.csv</em> which can be used by Mnemocrypt plugin to indicate some cryptographic identification information on flagged functions
- <em>./[training|tool]/ida\_databases/</em>:                          IDA databases associated to raw executables used
- <em>./[training|tool]/immediate\_crypto\_functions.json</em>:        Functions containing mnemonics from AES-NI or Intel SHA extensions instruction sets; such functions are directly considered by Mnemocrypt as cryptographic without even passing through the random forest classifier
- <em>./[training|tool]/immediate\_non\_crypto\_functions.json</em>:  Functions containing floating-point related mnemonics or only one basic block with few instructions; the content of the file is not used and mainly serves for tracking purpose
- <em>./tool/mnemocrypt\_predictions.csv</em>:              Results of Findcrypt run on all the executables from <em>./tool/</em> directory
- <em>./[training|tool]/raw\_executables/</em>:                         Contains the executables to analyze
- <em>./common/trained\_mnemocrypt.pkl</em>:                  Pre-trained Mnemocrypt model to avoid the user training the model if there is no need to customize it; can be generated with <em>./training/train\_mnemocrypt.py</em> script
- <em>./[training/tool]/unrecognized.json</em>:                        Unrecognized mnemonics during features computation; the content of the file is not used and is only relevant if the user is interested in customizing Mnemocrypt
- <em>./common/weights\_trained\_mnemocrypt.txt</em>           Weights of the features of <em>./common/trained\_mnemocrypt.pkl</em>, sorted in decreasing order of their importance and only playing informative role for the user (to get insight on what Mnemocrypt essentially is essentially basing its classification decisions on); generated along with <em>./common/trained\_mnemocrypt.pkl</em> by <em>./training/train\_mnemocrypt.py</em>

#### Documentation of command line arguments of some scripts
- <em>./common/building_wrapper.sh</em>: the first argument can take value "databases" or "features" for respectively IDA databases generation or features computation performed on already built IDA databases; the second argument may not take any value at all, in which case the script will not consider binaries from training set, it can also take the value "training" for the opposite case (only the training set is considered) or "all" value for processing both training and not training data (unless the user wants to customize Mnemocrypt model, there is normally no need to set the second argument).
- <em>./tool/plugin_batch.sh</em>: the first (and only) argument can take value "findcrypt" or "mnemocrypt" to respectively run the modified version of Findcrypt or Mnemocrypt in batch mode on all binaries (except the ones from the training set) with results export.
