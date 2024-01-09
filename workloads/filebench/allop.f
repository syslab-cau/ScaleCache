set mode quite firstdone
define fileset name=”testfset”,path=”/mnt/test”,
 entries=10000,filesize=4k,prealloc=50
define process name=”filecopy”,instances=2 {
 thread name=”filecopythread”,instances=2 {
 flowop openfile name=opfile”,
 filesetname=”testfset”,fd=1
 flowop createfile name=”crfile”,
 filesetname=”testfset”,fd=2
 flowop readwholefile name=”rdfile”,
 filesetname=”testfset”,fd=1
 flowop writewholefile name=”wrfile”,
 filesetname=”testfset”,fd=2
 flowop closefile name=”clfile1”,
 filesetname=”testfset”,fd=2
 flowop closefile name=”clfile2”,
 filesetname=”testfset”,fd=1
 }
}
