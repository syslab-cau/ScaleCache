#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

set $dir=/mnt/test
#set $nfiles=1000000
set $nfiles=64
#set $meandirwidth=10000
set $meandirwidth=64
#set $filesize=cvar(type=cvar-gamma,parameters=mean:131072;gamma:1.5)
#set $filesize=cvar(type=cvar-gamma,parameters=mean:19660800;gamma:1.5)
#set $filesize=cvar(type=cvar-gamma,parameters=mean:3221225472;gamma:1.5)
#set $filesize=cvar(type=cvar-uniform,parameters=mean:5368709120)
set $filesize=3g
set $nthreads=64
set $iosize=4k
set $meanappendsize=1m
#set $meanappendsize=16k
set $runtime=120


#define fileset name=bigfileset,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$meandirwidth,prealloc=80
define fileset name=bigfileset2,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$meandirwidth,reuse,prealloc=100
define fileset name=bigfileset,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$meandirwidth,reuse,prealloc=100



define process name=filewriter,instances=32
{
#thread name=filereaderthread,memsize=100m,instances=$nthreads
  thread name=filewriterthread,instances=1
  {
  #  flowop createfile name=createfile1,filesetname=bigfileset,fd=1
#    flowop createfile name=createfile1,filesetname="bigfileset",fd=2
#    flowop write name=myfop,filesetname=bigfileset,random,iosize=$iosize
#    flowop finishonbytes name=finish,value=3221225472
#    flowop writewholefile name=wrtfile1,srcfd=1,fd=1,iosize=$iosize
#    flowop writewholefile name=wrtfile1,srcfd=1,fd=1,random,iosize=$iosize
#    flowop closefile name=closefile1,fd=1
    #flowop openfile name=openfile1,filesetname=bigfileset,fd=1
    #flowop appendfilerand name=appendfilerand1,iosize=$meanappendsize,fd=1

#    flowop openfile name="openfile1",filesetname="bigfileset",fd=2
     flowop write name="rand-write1",filesetname="bigfileset",iosize=$iosize,random,directio
#    flowop closefile name="closefile1",fd=2

    #flowop closefile name=closefile2,fd=1
    #     flowop openfile name=openfile2,filesetname=bigfileset,fd=1
   # flowop readwholefile name=readfile1,fd=1,iosize=$iosize
   #     flowop closefile name=closefile3,fd=1
   #   flowop deletefile name=deletefile1,filesetname=bigfileset
   #     flowop statfile name=statfile1,filesetname=bigfileset
  }
}

define process name=filereader,instances=32
{
#thread name=filereaderthread,memsize=100m,instances=$nthreads
  thread name=filereaderthread,instances=1
  {
  #    flowop createfile name=createfile1,filesetname=bigfileset,fd=1
#    flowop createfile name=createfile1,filesetname="bigfileset",fd=2
#    flowop write name=myfop,filesetname=bigfileset,random,iosize=$iosize
#    flowop finishonbytes name=finish,value=3221225472
#    flowop writewholefile name=wrtfile1,srcfd=1,fd=1,iosize=$iosize
#    flowop writewholefile name=wrtfile1,srcfd=1,fd=1,random,iosize=$iosize
#    flowop closefile name=closefile1,fd=1
    #flowop openfile name=openfile1,filesetname=bigfileset,fd=1
    #flowop appendfilerand name=appendfilerand1,iosize=$meanappendsize,fd=1

#    flowop openfile name="openfile1",filesetname="bigfileset",fd=2
#     flowop write name="rand-write1",filesetname="bigfileset",iosize=$iosize,random
#    flowop closefile name="closefile1",fd=2

    #flowop closefile name=closefile2,fd=1
    flowop openfile name=openfile2,filesetname=bigfileset2,fd=1
       flowop readwholefile name=readfile1,fd=1,iosize=$iosize,directio
        flowop closefile name=closefile3,fd=1,directio
     #  flowop deletefile name=deletefile1,filesetname=bigfileset2
     #   flowop statfile name=statfile1,filesetname=bigfileset2
  }
}


echo  "File-server Version 3.0 personality successfully loaded"

run 60
#set mode quit alldone
