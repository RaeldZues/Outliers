import re
import codecs
from configparser import RawConfigParser
import pandas as pd
import glob2
import multiprocessing

pd.set_option('display.width', 500)
pd.set_option('max_colwidth', 500)
pd.set_option('display.max_rows', 80)


def read_reg(filename, encoding='utf-16'):
    with codecs.open(filename, encoding=encoding) as f:
        data = f.read()
    # removes the header containing the regedit info at the top of file
    data = re.sub(r'^[^\[]*\n', '', data, flags=re.S)
    # using the configuration parser to identify the sections of the file based on [section name] = section
    config = RawConfigParser(strict=False, allow_no_value=True)
    # dirty hack for "disabling" case-insensitive keys in "configparser"
    config.optionxform=str
    config.read_string(data)
    data = []
    # iterate over sections and keys and generate `data` for pandas.DataFrame
    for section in config.sections():
        # sets the stage for just the section or the Path if there is no data below it in the reg file
        if not config[section]:
            data.append([section, None, None, None])
        for key in config[section]:
            tp = val = None
            if config[section][key]:
                # This if statement identifies the value types and values
                # still have issues with value type if the value contains a path for windows removes the drive letter
                if ':' in config[section][key]:
                    tp = config[section][key].split(':')[0]
                    val = config[section][key].split(':')[1]
                else:
                    val = config[section][key].replace('"', '')
            data.append([section, key.replace('"', ''), tp, val])
    # This sets the dataframe with the data collected from above to the columns required.
    df = pd.DataFrame(data, columns=['Path', 'Key', 'Type', 'Value'])
    df.loc[df.Type.notnull() & df.Type.str.contains(r'^hex'), 'Value'] = \
        df.loc[df.Type.notnull() & df.Type.str.contains(r'^hex'), 'Value'].str.replace(r'\\\n', '')
    df.to_csv(r'.\\Registry_keys\by host converted\%s.csv' % (str(filename).split('\\')[-1].strip(".reg")),
              encoding='UTF-8', index=False)



if __name__ == '__main__':
    folder = glob2.glob(r".\\hostfolders\**\*.reg")
    for filename in folder:
        jobs = []
        p = multiprocessing.Process(read_reg(filename))
        jobs.append(p)
        p.start()
