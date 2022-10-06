#!/usr/bin/env python
from json import JSONDecodeError
import math
import pathlib
import time
from typing import Callable,Dict, Union
import pkg_resources
import sys
import os
import io
from os import stat_result, walk
try:

  import argparse
  import collections
  import copy
  import enum
  import glob

  import json
  import logging
  import re
  import shutil
  import stat
  import tempfile
  import zipfile
  from ast import literal_eval
  from collections import namedtuple
  from datetime import datetime, timedelta, timezone
  from json import JSONDecoder
  from operator import contains
  from platform import platform, release
  from pydoc import describe
  from time import strftime
  from typing import OrderedDict
  from urllib import response
  from urllib.parse import urlparse
  from urllib.request import Request
  from webbrowser import get

  import pygit2
  from pygit2 import Commit,Repository,GitError,Reference,UserPass,Index,Signature,RemoteCallbacks, Remote
  import requests
  from genericpath import isdir

except ImportError as ex:
    print(f'::error::Failed importing module {ex.name}, using interpreter {sys.executable}. \n Installed packages:')
    installed_packages = pkg_resources.working_set
    installed_packages_list = sorted(["%s==%s" % (i.key, i.version) for i in installed_packages])
    print('\n'.join(installed_packages_list))
    print(f'Environment: ')
    envlist="\n".join( [f"{k}={v}"  for k,v in sorted(os.environ.items())])
    print(f'{envlist}')
    raise

FORMAT = '%(asctime)s %(message)s'
logging.basicConfig(format=FORMAT)
logger:logging.Logger = logging.getLogger(__name__)
github_env= type('', (), {})()
tool_version= "1.0.5"
manifest={
    "name": "",
    "version": "",
    "home_assistant_domain": "slim_player",
    "funding_url": "https://esphome.io/guides/supporters.html",
    "builds": [
      {
        "chipFamily": "ESP32",
        "parts": [
        ]
      }
    ]
  }
artifacts_formats_outdir= '$OUTDIR'
artifacts_formats_prefix= '$PREFIX'
artifacts_formats =   [
  ['build/squeezelite.bin', '$OUTDIR/$PREFIX-squeezelite.bin'],
  ['build/recovery.bin', '$OUTDIR/$PREFIX-recovery.bin'],
  ['build/ota_data_initial.bin', '$OUTDIR/$PREFIX-ota_data_initial.bin'],
  ['build/bootloader/bootloader.bin', '$OUTDIR/$PREFIX-bootloader.bin'],
  ['build/partition_table/partition-table.bin ', '$OUTDIR/$PREFIX-partition-table.bin'],
]
class AttributeDict(dict):
    __slots__ = () 
    def __getattr__(self, name:str):
      try:
        return self[name.upper()]
      except Exception:
        try:
          return self[name.lower()]
        except Exception:
          for attr in self.keys():
            if name.lower() == attr.replace("'","").lower() :
              return self[attr]
    __setattr__ = dict.__setitem__



parser = argparse.ArgumentParser(description='Handles some parts of the squeezelite-esp32 build process')
parser.add_argument('--cwd', type=str,help='Working directory', default=os.getcwd())
parser.add_argument('--loglevel', type=str,choices={'CRITICAL','ERROR','WARNING','INFO','DEBUG','NOTSET'}, help='Logging level', default='INFO')
subparsers = parser.add_subparsers( dest='command', required=True)

parser_dir = subparsers.add_parser("list_files",
                                      add_help=False,
                                      description="List Files parser",
                                      help="Display the content of the folder")

parser_manifest = subparsers.add_parser("manifest",
                                      add_help=False,
                                      description="Manifest parser",
                                      help="Handles the web installer manifest creation")
parser_manifest.add_argument('--flash_file', required=True, type=str,help='The file path which contains the firmware flashing definition')
parser_manifest.add_argument('--max_count', type=int,help='The maximum number of releases to keep', default=3)
parser_manifest.add_argument('--manif_name', required=True,type=str,help='Manifest files name and prefix')
parser_manifest.add_argument('--outdir', required=True,type=str,help='Output directory for files and manifests')



parser_artifacts = subparsers.add_parser("artifacts",
                                      add_help=False,
                                      description="Artifacts parser",
                                      help="Handles the creation of artifacts files")
parser_artifacts.add_argument('--outdir', type=str,help='Output directory for artifact files', default='./artifacts/')


parser_pushinstaller = subparsers.add_parser("pushinstaller",
                                      add_help=False,
                                      description="Web Installer Checkout parser",
                                      help="Handles the creation of artifacts files")
parser_pushinstaller.add_argument('--target', type=str,help='Output directory for web installer repository', default='./web_installer/')
parser_pushinstaller.add_argument('--artifacts', type=str,help='Target subdirectory for web installer artifacts', default='./web_installer/')
parser_pushinstaller.add_argument('--source', type=str,help='Source directory for the installer artifacts', default='./web_installer/')
parser_pushinstaller.add_argument('--url', type=str,help='Web Installer clone url ', default='https://github.com/sle118/squeezelite-esp32-installer.git')
parser_pushinstaller.add_argument('--web_installer_branch', type=str,help='Web Installer branch to use ', default='main')
parser_pushinstaller.add_argument('--token', type=str,help='Auth token for pushing changes')
parser_pushinstaller.add_argument('--flash_file', type=str,help='Manifest json file path')
parser_pushinstaller.add_argument('--manif_name', required=True,type=str,help='Manifest files name and prefix')


parser_environment = subparsers.add_parser("environment",
                                      add_help=False,
                                      description="Environment parser",
                                      help="Updates the build environment")
parser_environment.add_argument('--env_file', type=str,help='Environment File',  default=os.environ.get('GITHUB_ENV'))
parser_environment.add_argument('--build', required=True, type=int,help='The build number')
parser_environment.add_argument('--node', required=True, type=str,help='The matrix node being built')
parser_environment.add_argument('--depth', required=True, type=int,help='The bit depth being built')
parser_environment.add_argument('--major', type=str,help='Major version', default='2')
parser_environment.add_argument('--docker', type=str,help='Docker image to use',default='sle118/squeezelite-esp32-idfv43')

parser_show = subparsers.add_parser("show",
                                      add_help=False,
                                      description="Show parser",
                                      help="Show the build environment")
parser_build_flags = subparsers.add_parser("build_flags",
                                      add_help=False,
                                      description="Build Flags",
                                      help="Updates the build environment with build flags")
parser_build_flags.add_argument('--mock', action='store_true',help='Mock release')
parser_build_flags.add_argument('--force', action='store_true',help='Force a release build')
parser_build_flags.add_argument('--ui_build', action='store_true',help='Include building the web UI')


def get_github_data(repo:Repository,api):
    base_url = urlparse(repo.remotes['origin'].url)
    url = f"https://api.github.com/repos{base_url.path.split('.')[-2]}/{api}"
    resp= requests.get(url, headers={"Content-Type": "application/vnd.github.v3+json"})
    return json.loads(resp.text)
def dump_directory(dir_path):
  # list to store files name
  res = []
  for (dir_path, dir_names, file_names) in walk(dir_path):
      res.extend(file_names)
  print(res)
class ReleaseDetails():
  version:str
  idf:str
  platform:str
  branch:str
  bitrate:str
  def __init__(self,tag:str) -> None:
    self.version,self.idf,self.platform,self.branch=tag.split('#')
    try:
      self.version,self.bitrate = self.version.split('-')
    except Exception:
      pass
  def get_attributes(self):
    return {
      'version': self.version,
      'idf': self.idf,
      'platform': self.platform,
      'branch': self.branch,
      'bitrate': self.bitrate
    }
  def format_prefix(self)->str:
    return f'{self.branch}-{self.platform}-{self.version}'
  def get_full_platform(self):
    return f"{self.platform}{f'-{self.bitrate}' if self.bitrate is not None else ''}"
  
class BinFile():
  name:str
  offset:int
  source_full_path:str
  target_name:str
  target_fullpath:str
  artifact_relpath:str
  def __init__(self, source_path,file_build_path:str, offset:int,release_details:ReleaseDetails,build_dir) -> None:
    self.name = os.path.basename(file_build_path).rstrip()
    self.artifact_relpath = os.path.relpath(file_build_path,build_dir).rstrip()
    self.source_path = source_path
    self.source_full_path = os.path.join(source_path,file_build_path).rstrip()
    self.offset = offset
    self.target_name= f'{release_details.format_prefix()}-{self.name}'.rstrip()
  def get_manifest(self):
    return { "path": self.target_name , "offset": self.offset  }
  def copy(self,target_folder)->str:
    self.target_fullpath=os.path.join(target_folder,self.target_name)
    logger.debug(f'file {self.source_full_path} will be copied to {self.target_fullpath}')
    try:
      os.makedirs(target_folder, exist_ok=True)
      shutil.copyfile(self.source_full_path, self.target_fullpath, follow_symlinks=True)
    except Exception as ex:
      print(f'::error::Error while copying {self.source_full_path} to {self.target_fullpath}' )
      print(f'::error::Content of {os.path.dirname(self.source_full_path.rstrip())}:')
      print('\n::error::'.join(get_file_list(os.path.dirname(self.source_full_path.rstrip()))))
      raise
    return self.target_fullpath
  def get_attributes(self):
    return { 
      'name':self.target_name,
      'offset':self.offset,
      'artifact_relpath':self.artifact_relpath
    }

class PlatformRelease():
  name:str
  description:str
  url:str=''
  zipfile:str=''
  tempfolder:str
  release_details:ReleaseDetails
  flash_parms={}
  build_dir:str
  has_artifacts:bool
  branch:str
  assets:list
  bin_files:list
  name_prefix:str
  def get_manifest_name(self)->str:
    return f'{self.name_prefix}-{self.release_details.format_prefix()}.json'
  def __init__(self,git_release,flash_parms,build_dir, branch,name_prefix) -> None:
    self.name = git_release.tag_name
    self.description=git_release.body
    self.assets = git_release['assets']
    self.has_artifacts = False
    self.name_prefix = name_prefix
    if len(self.assets)>0:
      if self.has_asset_type():
        self.url=self.get_asset_from_extension().browser_download_url
      if self.has_asset_type('.zip'):
        self.zipfile=self.get_asset_from_extension(ext='.zip').browser_download_url
        self.has_artifacts = True
    self.release_details=ReleaseDetails(git_release.name)
    self.bin_files = list()
    self.flash_parms = flash_parms
    self.build_dir = build_dir
    self.branch = branch
  def process_files(self,outdir:str)->list:
    parts = []
    for f in self.bin_files:
      f.copy(outdir)
      parts.append(f.get_manifest())

  def get_asset_from_extension(self,ext='.bin'):
    for a in self.assets:
      filename=AttributeDict(a).name
      file_name, file_extension = os.path.splitext(filename)
      if file_extension == ext:
        return AttributeDict(a)
    return None
  def has_asset_type(self,ext='.bin')->bool:
    return self.get_asset_from_extension(ext) is not None        
  def platform(self):
    return self.release_details.get_full_platform()
  def get_zip_file(self):
    self.tempfolder = extract_files_from_archive(self.zipfile)
    logger.info(f'Artifacts for {self.name} extracted to {self.tempfolder}')
    try:
      for artifact in artifacts_formats:
        base_name =  os.path.basename(artifact[0]).rstrip().lstrip()
        self.bin_files.append(BinFile(self.tempfolder,artifact[0],self.flash_parms[base_name],self.release_details,self.build_dir))
        has_artifacts = True
    except Exception:
      self.has_artifacts = False
  def cleanup(self):
    logger.info(f'removing {self.name}  temp directory {self.tempfolder}')
    shutil.rmtree(self.tempfolder)
  def get_attributes(self):
    return {
      'name':self.name,
      'branch':self.branch,
      'description':self.description,
      'url':self.url,
      'zipfile':self.zipfile,
      'release_details':self.release_details.get_attributes(),
      'bin_files': [b.get_attributes() for b in self.bin_files],
      'manifest_name': self.get_manifest_name()
    }

class Releases():
  _dict:dict = collections.OrderedDict()
  maxcount:int =0
  branch:str=''
  repo:Repository=None
  manifest_name:str
  def __init__(self,branch:str,maxcount:int=3) -> None:
    self.maxcount = maxcount
    self.branch = branch
  def count(self,value:PlatformRelease)->int:
    content=self._dict.get(value.platform())
    if content == None:
      return 0
    return len(content)
  def get_platform(self,platform:str)->list:
    return self._dict[platform]
  def get_platform_keys(self):
    return self._dict.keys()
  def get_all(self)->list:
    result:list=[]
    for platform in [self.get_platform(platform) for platform in self.get_platform_keys()]:
      for release in platform:
        result.append(release)
    return result
  def append(self,value:PlatformRelease):
      # optional processing here
      if self.count(value) == 0:
          self._dict[value.platform()] = []
      if self.should_add(value):
        logger.info(f'Adding release {value.name} to the list')
        self._dict[value.platform()].append(value)
      else:
        logger.info(f'Skipping release {value.name}')
  def get_attributes(self):
    res = []
    release:PlatformRelease
    for release in self.get_all():
      res.append(release.get_attributes())
    return res
  def get_minlen(self)->int:
      return min([len(self.get_platform(p)) for p in self.get_platform_keys()])
  def got_all_packages(self)->bool:
    return self.get_minlen() >=self.maxcount
  def should_add(self,release:PlatformRelease)->bool:
    return self.count(release) <=self.maxcount
  def add_package(self,package:PlatformRelease, with_artifacts:bool=True):
    if self.branch != package.branch:
      logger.info(f'Skipping release {package.name} from branch {package.branch}')
    elif package.has_artifacts or not with_artifacts:
      self.append(package)
  @classmethod
  def get_last_commit(cls)->Commit:
    if cls.repo is None:
      cls.get_repository(os.getcwd())
    return cls.repo[cls.repo.head.target]
  @classmethod
  def get_repository(cls,path:str=os.getcwd())->Repository:
    if cls.repo is None:  
      try:
        logger.info(f'Opening repository from {path}')
        cls.repo=Repository(path=path)
      except GitError as ex:
        print(f'::error::Error while trying to access the repository.')
        print(f'::error::Content of {path}:')
        print('\n::error::'.join(get_file_list(path)))
        raise 
    return cls.repo
  @classmethod
  def resolve_commit(cls,repo:Repository,commit_id:str)->Commit:
    commit:Commit
    reference:Reference
    commit, reference = repo.resolve_refish(commit_id)
    return commit

  @classmethod
  def get_release_branch(cls,repo:Repository,platform_release)->str:
    match = [t for t in repo.branches.with_commit(platform_release.target_commitish)]
    no_origin = [t for t in match if 'origin' not in t]
    if len(no_origin) == 0 and len(match) > 0:
      return match[0].split('/')[1]
    elif len(no_origin) >0:
      return no_origin[0]
    return ''
  @classmethod
  def get_flash_parms(cls,file_path):
    flash = parse_json(file_path)
    od:collections.OrderedDict = collections.OrderedDict()
    for z in flash['flash_files'].items():
      base_name:str = os.path.basename(z[1])
      od[base_name.rstrip().lstrip()] = literal_eval( z[0])
    return collections.OrderedDict(sorted(od.items()))    
  @classmethod
  def get_releases(cls,flash_file_path,maxcount:int,name_prefix):
    repo=Releases.get_repository(os.getcwd())
    flash_parms = Releases.get_flash_parms(flash_file_path)
    packages:Releases  = cls(branch=repo.head.shorthand,maxcount=maxcount)
    build_dir=os.path.dirname(flash_file_path)
    for page in range(1,999):
      logger.debug(f'Getting releases page {page}')
      releases = get_github_data(repo,f'releases?per_page=50&page={page}')
      if len(releases)==0:
        logger.debug(f'No more release found for page {page}')
        break
      for release_entry in [AttributeDict(platform) for platform in releases]:
        packages.add_package(PlatformRelease(release_entry,flash_parms,build_dir,Releases.get_release_branch(repo,release_entry),name_prefix))
        if packages.got_all_packages():
          break
      if packages.got_all_packages():
        break

    return packages
  def update(self, *args, **kwargs):
      if args:
          if len(args) > 1:
              raise TypeError("update expected at most 1 arguments, "
                              "got %d" % len(args))
          other = dict(args[0])
          for key in other:
              self[key] = other[key]
      for key in kwargs:
          self[key] = kwargs[key]

  def setdefault(self, key, value=None):
      if key not in self:
          self[key] = value
      return self[key]
def set_workdir(args):
    logger.info(f'setting work dir to: {args.cwd}')
    os.chdir(os.path.abspath(args.cwd))
def parse_json(filename:str):
    fname = os.path.abspath(filename)
    folder:str = os.path.abspath(os.path.dirname(filename))
    logger.info(f'Opening json file {fname} from {folder}')    
    try:
      with open(fname) as f:
        content=f.read()  
        logger.debug(f'Loading json\n{content}')
        return json.loads(content)
    except JSONDecodeError as ex:
      print(f'::error::Error parsing {content}')
    except Exception as ex:
      print(f'::error::Unable to parse flasher args json file. Content of {folder}:')
      print('\n::error::'.join(get_file_list(folder)))
      raise 

def write_github_env(args):
  logger.info(f'Writing environment details to {args.env_file}...')
  with open(args.env_file,  "w") as env_file:
    for attr in [attr for attr in dir(github_env) if not attr.startswith('_')]:
      line=f'{attr}={getattr(github_env,attr)}'
      logger.info(line)
      env_file.write(f'{line}\n')
      os.environ[attr] = str(getattr(github_env,attr))
  logger.info(f'Done writing environment details to {args.env_file}!')
def set_workflow_output(args):
  logger.info(f'Outputting job variables ...')
  for attr in [attr for attr in dir(github_env) if not attr.startswith('_')]:
    # use print instead of logger, as we need the raw output without the date/time prefix from logging 
    print(f'::set-output name={attr}::{getattr(github_env,attr)}')
    os.environ[attr] = str(getattr(github_env,attr))
  logger.info(f'Done outputting job variables!')  

def format_commit(commit):
  #463a9d8b7 Merge branch 'bugfix/ci_deploy_tags_v4.0' into 'release/v4.0' (2020-01-11T14:08:55+08:00)
  dt = datetime.fromtimestamp(float(commit.author.time), timezone( timedelta(minutes=commit.author.offset) ))
  timestr = dt.strftime('%c%z')
  cmesg= commit.message.replace('\n', ' ' )
  return f'{commit.short_id} {cmesg} ({timestr}) <{commit.author.name}>'.replace('  ', ' ', )

def format_artifact_name(base_name:str='',args = AttributeDict(os.environ)):
  return f'{base_name}{args.branch_name}-{args.node}-{args.depth}-{args.major}{args.build}'

def handle_build_flags(args):
  set_workdir(args)
  logger.info('Setting global build flags')
  last:Commit = Releases.get_last_commit()
  commit_message:str= last.message.replace('\n', ' ')
  github_env.mock=1 if args.mock else 0
  github_env.release_flag=1 if args.mock  or args.force or 'release' in commit_message.lower() else 0
  github_env.ui_build=1 if args.mock or args.ui_build or '[ui-build]' in commit_message.lower() or github_env.release_flag==1 else 0
  set_workflow_output(github_env)

def handle_environment(args):
    set_workdir(args)
    logger.info('Setting environment variables...')

    last:Commit = Releases.get_last_commit()
    commit_message:str= last.message.replace('\n', ' ')
    github_env.author_name=last.author.name
    github_env.author_email=last.author.email
    github_env.committer_name=last.committer.name
    github_env.committer_email=last.committer.email    
    github_env.node=args.node
    github_env.depth=args.depth
    github_env.major=args.major
    github_env.build=args.build
    github_env.DEPTH=args.depth
    github_env.TARGET_BUILD_NAME=args.node
    github_env.build_version_prefix=args.major
    github_env.branch_name=re.sub('[^a-zA-Z0-9\-~!@_\.]', '', Releases.get_repository().head.shorthand)
    github_env.BUILD_NUMBER=str(args.build)
    github_env.tag=f'{args.node}.{args.depth}.{args.build}.{github_env.branch_name}'.rstrip()
    github_env.last_commit=commit_message
    
    github_env.DOCKER_IMAGE_NAME=args.docker
    github_env.name=f"{args.major}.{str(args.build)}-{args.depth}#v4.3#{args.node}#{github_env.branch_name}"
    github_env.artifact_prefix=format_artifact_name('squeezelite-esp32-',github_env)
    github_env.artifact_file_name=f"{github_env.artifact_prefix}.zip"
    github_env.artifact_bin_file_name=f"{github_env.artifact_prefix}.bin"
    github_env.PROJECT_VER=f'{args.node}-{ args.build }'
    github_env.description='### Revision Log<br><<~EOD\n'+'<br>\n'.join(format_commit(c) for i,c in enumerate(Releases.get_repository().walk(last.id,pygit2.GIT_SORT_TIME)) if i<10)+'\n~EOD'
    write_github_env(args)

def handle_artifacts(args):
    set_workdir(args)
    logger.info(f'Handling artifacts')
    for attr in artifacts_formats:
      target:str=attr[1].replace(artifacts_formats_outdir,args.outdir).replace(artifacts_formats_prefix,format_artifact_name())
      logger.debug(f'file {attr[0]} will be copied to {target}')
      try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(attr[0].rstrip(), target, follow_symlinks=True)
      except Exception as ex:
        print(f'::error::Error while copying to {target}' )
        print(f'::error::Content of {os.path.dirname(attr[0].rstrip())}:')
        print('\n::error::'.join(get_file_list(os.path.dirname(attr[0].rstrip()))))
        raise

def delete_folder(path):
  '''Remov Read Only Files'''
  for root, dirs, files in os.walk(path,topdown=True):
      for dir in dirs:
        fulldirpath=os.path.join(root, dir)
        logger.debug(f'Drilling down in {fulldirpath}')
        delete_folder(fulldirpath)
      for fname in files:
          full_path = os.path.join(root, fname)
          logger.debug(f'Setting file read/write {full_path}')
          os.chmod(full_path ,stat.S_IWRITE)
          logger.debug(f'Deleting file {full_path}')
          os.remove(full_path)
  if os.path.exists(path):
    logger.debug(f'Changing folder read/write {path}')
    os.chmod(path ,stat.S_IWRITE)
    logger.warning(f'Deleting Folder {path}')
    os.rmdir(path)
def get_file_stats(path)->tuple[int,str,str]:
  fstat:os.stat_result = pathlib.Path(path).stat()
    # Convert file size to MB, KB or Bytes
  mtime = time.strftime("%X %x", time.gmtime(fstat.st_mtime))
  if (fstat.st_size > 1024 * 1024):
      return math.ceil(fstat.st_size / (1024 * 1024)), "MB", mtime
  elif (fstat.st_size > 1024):
      return math.ceil(fstat.st_size / 1024), "KB", mtime
  return fstat.st_size, "B", mtime

def get_file_list(root_path, max_levels:int=2 )->list:
  outlist:list=[]
  for root, dirs, files in os.walk(root_path):
      path = root.split(os.sep)
      if len(path) <= max_levels:
        outlist.append(f'\n{root}')
        for file in files:
          full_name=os.path.join(root, file)
          fsize,unit,mtime = get_file_stats(full_name)
          outlist.append('{:s} {:8d} {:2s} {:18s}\t{:s}'.format(len(path) * "---",fsize,unit,mtime,file))
  return outlist
def get_recursive_list(path)->list:
  outlist:list=[]
  for root, dirs, files in os.walk(path,topdown=True):
      for dir in dirs:
        outlist.extend(get_recursive_list(os.path.join(root, dir)))
      for fname in files:
        outlist.append(fname)
  # if os.path.exists(path):
  #   outlist.append(path)
  outlist.sort()
  return outlist

def handle_manifest(args):
  set_workdir(args)
  logger.info(f'Creating the web installer manifest')
  env = AttributeDict(os.environ)
  if not os.path.exists(os.path.dirname(args.outdir)):
    logger.info(f'Creating target folder {args.outdir}')
    os.makedirs(args.outdir, exist_ok=True)
  releases:Releases = Releases.get_releases(args.flash_file, args.max_count,args.manif_name)
  release:PlatformRelease
  for release in releases.get_all():
    release.get_zip_file()
    man = copy.deepcopy(manifest)
    man['manifest_name'] = release.get_manifest_name()
    man['builds'][0]['parts'] = release.process_files(args.outdir)
    man['name'] = release.platform()
    man['version'] = release.release_details.version
    logger.debug(f'Generated manifest: \n{json.dumps(man,indent=4)}')
    fullpath=os.path.join(args.outdir,release.get_manifest_name())
    logger.info(f'Writing manifest to {fullpath}')
    with open(fullpath, "w") as f:
        json.dump(man,f,indent=4)
    release.cleanup()
  mainmanifest=os.path.join(args.outdir,args.manif_name)
  logger.info(f'Writing main manifest {mainmanifest}')
  with open(mainmanifest,'w') as f:
      json.dump(releases.get_attributes(),f,indent=4)
def get_new_file_names(manifest:str,source:str)->collections.OrderedDict():
  artifacts = parse_json(os.path.join(source,manifest))
  new_release_files:dict = collections.OrderedDict()
  for artifact in artifacts:
    for name in [f["name"]  for f in artifact["bin_files"]]:
      new_release_files[name] = artifact
    new_release_files[artifact['manifest_name']] = artifact['name']
  return new_release_files

def copy_no_overwrite(source:str,target:str)  :
  sfiles = os.listdir(source)
  for f in sfiles:
    source_file = os.path.join(source,f)
    target_file  = os.path.join(target,f)
    if not os.path.exists(target_file):
      logger.info(f'Copying {f} to target')
      shutil.copy(source_file, target_file)
    else:
      logger.debug(f'Skipping existing file {f}')

def get_changed_items(repo:Repository)->Dict:
  changed_filemode_status_code: int = pygit2.GIT_FILEMODE_TREE
  original_status_dict: Dict[str, int] = repo.status()
  # transfer any non-filemode changes to a new dictionary
  status_dict: Dict[str, int] = {}
  for filename, code in original_status_dict.items():
      if code != changed_filemode_status_code:
          status_dict[filename] = code
  return status_dict

def is_dirty(repo:Repository)->bool:
  return len(get_changed_items(repo)) > 0 

def push_if_change(repo:Repository, token:str):
  if is_dirty(repo):
    logger.info(f'Changes found. Preparing commit')
    env = AttributeDict(os.environ)
    index:Index = repo.index
    index.add_all() 
    index.write()
    reference=repo.head.name
    author = Signature(env.author_name,env.author_email)
    committer = Signature(env.committer_name, env.committer_email)
    message = f'Web installer for {format_artifact_name()}'
    tree = index.write_tree()
    commit = repo.create_commit(reference, author, committer, message, tree,[repo.head.target])
    origin:Remote=repo.remotes['origin']
    logger.info(f'Pushing commit {format_commit(repo[commit])} to url {origin.url}')
    credentials = UserPass(token, 'x-oauth-basic')  # passing credentials
    remote:Remote =   repo.remotes['origin']
    remote.credentials = credentials
    remote.push([reference],callbacks= RemoteCallbacks(UserPass(token, 'x-oauth-basic')))
  else:
    logger.warning(f'No change found. Skipping update')

def update_files(target_artifacts:str,manif_name:str,source:str):
  new_list:dict = get_new_file_names(manif_name, os.path.abspath(source))
  if os.path.exists(target_artifacts):
    logger.info(f'Removing obsolete files from {target_artifacts}')
    for f in get_recursive_list(target_artifacts):
      if f not in new_list.keys():
          full_target = os.path.join(target_artifacts,f)
          logger.warning(f'Removing obsolete file {f}')
          os.remove(full_target)
  else:
    logger.info(f'Creating target folder {target_artifacts}')
    os.makedirs(target_artifacts, exist_ok=True)
  logger.info(f'Copying installer files to {target_artifacts}:')
  copy_no_overwrite(os.path.abspath(source), target_artifacts)

def handle_pushinstaller(args):
  set_workdir(args)
  logger.info('Pushing web installer updates... ')
  target_artifacts = os.path.join(args.target,args.artifacts)
  if os.path.exists(args.target):
    logger.info(f'Removing files (if any) from {args.target}')
    delete_folder(args.target)
  logger.info(f'Cloning from {args.url} into {args.target}')
  repo = pygit2.clone_repository(args.url,args.target)
  repo.checkout_head()
  update_files(target_artifacts,args.manif_name,args.source)
  push_if_change(repo,args.token)
  repo.state_cleanup()
  
def handle_show(args):
  logger.info('Show')


def extract_files_from_archive(url):
  tempfolder= tempfile.mkdtemp()
  platform = requests.get(url)
  z = zipfile.ZipFile(io.BytesIO(platform.content))
  z.extractall(tempfolder)
  return tempfolder
def handle_list_files(args):
  print(f'Content of {args.cwd}:')
  print('\n'.join(get_file_list(args.cwd)))
parser_environment.set_defaults(func=handle_environment, cmd='environment')
parser_artifacts.set_defaults(func=handle_artifacts, cmd='artifacts')
parser_manifest.set_defaults(func=handle_manifest, cmd='manifest')
parser_pushinstaller.set_defaults(func=handle_pushinstaller, cmd='installer')
parser_show.set_defaults(func=handle_show, cmd='show')    
parser_build_flags.set_defaults(func=handle_build_flags, cmd='build_flags')    
parser_dir.set_defaults(func=handle_list_files, cmd='list_files')


def main():
  args = parser.parse_args()
  logger.setLevel(logging.getLevelName(args.loglevel))
  logger.info(f'build_tools version : {tool_version}')    
  logger.debug(f'Processing command {args.command}')
  func:Callable = getattr(args, 'func', None)
  if func is not None:
      # Call whatever subcommand function was selected
      func(args)
  else:
      # No subcommand was provided, so call help
      parser.print_usage()

if __name__ == '__main__':
  main()
  