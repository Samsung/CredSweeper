# Train credential detection model

This code will allow you to retrain model on the CredData dataset

## Preparation

- Make sure that you are using Python 3.7.10 or higher

- Download CredData dataset

```bash
git clone https://github.com/Samsung/CredData
cd CredData
pip install PyYAML
python download_data.py --data_dir data
```

- Go back to `CredSweeper/experiment` directory
- Install the requirements

```bash
pip install -r requirements.txt
``` 

- Make sure that `credsweeper` in the `PYTHONPATH`. You can add it with 

```bash
export PYTHONPATH=<CredSweeper directory>:$PYTHONPATH
``` 

Example:

```bash
export PYTHONPATH=/home/user/code/CredSweeper:$PYTHONPATH
``` 

## Run

- Launch the experiment with

```bash
python main.py --data <CredData location> -j <num parallel process to run>
```

Example:

```bash
python main.py --data /home/user/datasets/CredData -j 16
``` 

- Resulting model will be saved to `results/ml_model_at-<timestamp>.h5`. You 
now can copy this model to the `credsweeper/ml_model/ml_model.h5`


