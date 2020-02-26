from setuptools import setup
setup(name="tpm_futurepcr",
      version="1.1",
      description="Calculate future TPM PCR[4] after a kernel upgrade",
      url="https://github.com/grawity/tpm_futurepcr",
      author="Mantas Mikulėnas",
      author_email="grawity@gmail.com",
      license="MIT",
      packages=["tpm_futurepcr"],
      install_requires=["signify"],
      entry_points={
          "console_scripts": [
              "tpm_futurepcr = tpm_futurepcr:main",
          ],
      })
