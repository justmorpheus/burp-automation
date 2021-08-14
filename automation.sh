#!/bin/bash



install(){
			git clone $1
			echo -e "\n"
                        cd $(echo $1|awk -F/ '{print $5}'|cut -d. -f1)
                        echo -e "Current Folder: `pwd` \n"
                        wget "https://portswigger.net/burp/releases/download?product=pro&version=2021.6.2&type=Jar" -O burpsuite_pro_v2021.6.2.jar
                        echo "Burpsuite Jar successfully downloaded. \n"
			mkdir -p ~/.java/.userPrefs/burp
                        cp prefs.xml ~/.java/.userPrefs/burp/prefs.xml
			cat ~/.java/.userPrefs/burp/prefs.xml
			echo -e "Burp activation complete. \n"
                        echo -e "\n"
                        wget https://github.com/vmware/burp-rest-api/releases/download/v2.1.0/burp-rest-api-2.1.0.jar
                        echo -e "\n"
			cd burp-ext
			wget https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.2/jython-standalone-2.7.2.jar
			wget https://repo1.maven.org/maven2/org/jruby/jruby-complete/9.2.19.0/jruby-complete-9.2.19.0.jar
			cd ..
			
			chmod +x burp-rest-api.sh
			sudo apt-update -y
			if pgrep -x "Xvfb" > /dev/null
			then
    				echo "Xvfb Running"
				export DISPLAY=:99
			else
    				echo "Stopped"
				sudo apt install xvfb -y
                 		echo -e "Setting up in-memory display xvfb"
                 		Xvfb :99 &
                 		export DISPLAY=:99
                 		sudo apt-get install libfontconfig1 libxrender1 -y
				apt install -y python3
			fi
                        
			if ! python3 --version ; then
                                echo -e "python3 is not installed \n"
                                exit 1
                        else
				if command -v apt-get >/dev/null; then
					sudo apt install python3-testresources -y
					echo -e "apt-get is used for installing python3-testresources"
				elif command -v yum >/dev/null; then

					echo "yum is used here, currently not supported for centos. Use docker instead"
					exit 1
				else
  					echo "I have no Idea what im doing here"
				fi
                               
				echo -e "\n"
				python3 -m pip install -r requirements.txt
				echo -e "\n"
                                python3 -m robot -d output fuzzing.robot
				echo -e "\n"

    fi
}
if type -p java; then
    echo -e "Java PATH found \n"
    _java=java
elif [[ -n "$JAVA_HOME" ]] && [[ -x "$JAVA_HOME/bin/java" ]];  then
    echo -e "Java executable in JAVA_HOME \n"   
    _java="$JAVA_HOME/bin/java"
else
    echo -e "No java found | Instalingl Java 14.0.1. \n"
    wget https://download.java.net/java/GA/jdk14.0.1/664493ef4a6946b186ff29eb326336a2/7/GPL/openjdk-14.0.1_linux-x64_bin.tar.gz
    tar xvfz openjdk-14.0.1_linux-x64_bin.tar.gz
    mkdir /usr/lib/jvm/
    mv jdk-14.0.1 /usr/lib/jvm/ 
    echo -ne '\n' |update-alternatives --install "/usr/bin/javac" "javac" "/usr/lib/jvm/jdk-14.0.1/bin/javac" 1081
    echo -ne '\n' |update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jdk-14.0.1/bin/java" 1081
    echo -ne '\n' |update-alternatives --set "javac" "/usr/lib/jvm/jdk-14.0.1/bin/javac"
    echo -ne '\n' |update-alternatives --set "java" "/usr/lib/jvm/jdk-14.0.1/bin/java"
    echo -ne '\n' |update-alternatives --config java
    java -version
    echo -e "Java 14.0.1 has been installed"
fi

if [[ "$_java" ]]; then
   
    version=$(java -version 2>&1|awk -F '"' '/version/ {print $2}'|awk -F "." '{print $1}')
    echo Java version "$version"
    if [[ "$version" == "14" ]]; then
        echo -e "Version is greater than 1.8. Compatible version is Java 14. \n"
    else         
        echo -e "Install java 14 \n"
	exit 1
    fi
fi
if command -v apt-get >/dev/null; then
	 if ! dpkg -s "python3-pip" >/dev/null 2>&1; then
		 sudo apt update -y
		 sudo apt-get install python3-pip -y
	fi
elif command -v yum >/dev/null; then
	echo "yum is used here"
else
	echo "This package manager is not supported"
fi

if [ -z "$1" ]
then
	echo -e "No git repository is passed as argument. Pass in the format: https://git_username:password@github.com/folder.git \n"
	exit 1
else

		
	if [ -d "$(echo $1|awk -F/ '{print $5}'|cut -d. -f1)" ]; then
		echo -e "Directory exist, deleting the old directory. \n"
		rm -rf "$(echo $1|awk -F/ '{print $5}'|cut -d. -f1)"
		echo -e "\n"
		install "$1"

	else
		echo -e "\n"
		install "$1"
	fi
		
	

fi
