# Augmentation of CredData data

## Requirement

``` bash
$ pip install -qr requirements.txt
```

## Run

``` bash
$ python main.py <CredData location> <True stake> <Scale ratio>
```

Such as:

``` bash
$ python main.py "/path/to/CredData" 0.1 3
```

As a result `aug_data` folder will be created in `<CredData location>`

## Password samples

To improve the quality of the augmented data and their suitability for training the ML model, such credentials as Passwords are replaced with samples from real passwords during the generation of the augmented dataset.

Password samples consist of 2 dataset: only passwords contains words inside and dataset containing many kinds of passwords including word passwords, number-letter keys, multi-word passwords, and others.

Passwords contains words set was generated on own sets of passwords with words obtained during the collection of the dataset
A more extensive set of passwords was created from several sets of passwords from https://github.com/danielmiessler/SecLists and own sets of passwords obtained during the collection of the dataset
