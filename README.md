# NSE - Peer to Peer Network Size Estimation 
This is a NSE which implements the protocol described in [Efficient and Secure Decentralized Network Size Estimation](https://doi.org/10.1007/978-3-642-30045-5_23) by Nathan Evans, Bartlomiej Polot & Christian Grothoff, and is also used by GNUnet. Additional information can be found in the project documentation in `docs`.
## NSE
The main NSE that every peer in the network runs to calculate the size is in `NSE.py`, which takes a config file in the `.ini` format by adding a filepath to the command with `-c`. A default config file called `default.ini` is provided, which will be used if no filepath to a config file is given.  An example of a NSE startup command is given below, make sure that your Python installation is 3.8 or newer. Furthermore, the NSE depends on the `nse_util.py` and a functioning Gossip module, which needs to be started beforehand and whose address and port have to be specified in the config, of which the format should follow the example given in `default.ini`. The Gossip module itself is not part of this repository.
```bash
python3 NSE.py -c config.ini
```
## Test
To show that the NSE is working as intended, and to present a sample of how the NSE works in practice, a testing environment is provided. This consists of the `test_module.py` which simulates a peer to peer network for the NSE, the `gossip_mockup.py` which is a Gossip dummy implemented by the team behind the Peer to Peer Security lecture at TUM, and the bash script `test.sh` which runs the components of the test. The testing module also reads information from the `default.ini`, which set the parameters for the test, e.g. how many peers are simulated or how many rounds the test should run for. If you wish to change these parameters, simply edit them inside the `default.ini` config file before building.
### Building the Docker image
Building the Docker image can be achieved in the following way inside your system's shell:
```bash 
docker build -t nse $URL
```
where `$URL` is to be replaced with the URL to the git repository. This will create a docker image named "nse". The Docker image should then be executed by running
```bash
docker run -it -v nse_vol:/app nse
```
The `-it` option makes it possible to interact with the shell inside the docker image, which is important to be able to cancel the execution at the end of the test with CTRL-C. `-v nse_vol:/app` will create a volume named "nse_vol", which represents the directory of the image locally on your machine. This makes it possible to look at files generated by running the image afterwards, including a `chart.png` file which the test creates to visualise the estimates of the network against the actual number of peers participating. With
```bash
docker volume inspect nse_vol
```
the mount point of the volume is then printed. Most likely you'll have to switch to root to access the volume.
