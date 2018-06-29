
from Filter import *
import re
import json
from Utils import *
import ctypes, os
import readCapture

class Parser(Thread):

    """Thread chargé d'ecouter les instruction utilisateur et de les traiter . Gere aussi le thread chargé de filtrer les paquets reseaux """

    def __init__(self):
        Thread.__init__(self)
        self.__td_filter = Filter()
        self.__isrunning = True


    def run(self):
        #On check si le programmes est bien lancé avec les priviléges administrateurs , sans quoi il ne peut tourner ( besoin de ca pour descendre les paquets dans le userland )
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

        if not is_admin :
            print("Can't run the program , \nPlease execute Supfirewall with administrator privilege")
            input("\nPress Enter to close the program ")
            return


        # On demarre le filtrage de paquet sur un thread séparé
        self.__td_filter.start()

        while self.__isrunning:
            command = input("cmd: ")
            self.parse(command)


    def run_filter(self):
        self.__td_filter = Filter()
        self.__td_filter.start()


    def update_rules_table(self,mode,port,ip_source,protocol):
        """Met a jour la table des règles en fonction des info extraite dans la commande """
        # On stop le filtrage de paquets le temps de la mise à jour de la table des régles
        self.__td_filter.stop()
        self.__td_filter.join()

        with open("rules_table.txt", "r") as file:
            raw_data = file.read()
            rules_table = json.loads(raw_data)

        #Si le mode est Remove , on cherche dans le fichier la regle a supprimer
        if mode=='R':
            actualized_rules={"rules": []}
            rule_to_del_found=False
            for rule in rules_table['rules']:
                if rule['port']!=port  or rule['ip_source']!=ip_source or rule['protocol']!=protocol:
                    actualized_rules['rules'].append(rule)
                else:
                    rule_to_del_found = True
                    print("Following rule deleted : ip denied : {0}, port denied : {1} , protocol denied : {2}".format(ip_source, port, protocol))
            rules_table= actualized_rules
            if not rule_to_del_found:
                print("This rule doesn't exist ")

        #Si on est en mode ajout de regle , on check si la regle n existe pas avant d'ajouter la regle
        if mode == 'A':
            rule_existing=False
            for rule in rules_table['rules']:
                if rule['port'] == port  and rule['ip_source'] == ip_source  and rule['protocol']==protocol:
                    rule_existing=True
                    break
            if not rule_existing:
                rules_table['rules'].append({"port": port,"ip_source":ip_source,"protocol":protocol})
                print("New rule created : ip denied : {0}, port denied : {1} , protocol denied : {2}".format(ip_source,port,protocol))
            else:
                print("This rule already exists")

        rules_data_encoded=json.dumps(rules_table)
        with open("rules_table.txt", "w") as file:
            file.write('\n{}'.format(rules_data_encoded))

        self.run_filter()

    def parse(self,command):
        """Traite le commande avec la fonction associée"""

        if self.check_command(command): #commandes creation/suppretion regle avec ip,port et protocole
            mode = command[13]
            port = self.extract_data(command,'-p')
            ip_source = self.extract_data(command, '-ips')
            protocol=self.extract_data(command,'-Pt')
            self.update_rules_table(mode, port, ip_source,protocol)

        elif re.match(r"supfirewall\s-f\s[\w|.]+[ ]*$", command) != None : #commande filtrage d'un fichier pcapng a partir des regle de la table des regles vers un output pcapng
            pcapfile_name= self.extract_data(command,'-f')
            print("Parsing pcapng file .. ")
            readCapture.filteringPcapFile(pcapfile_name)

        elif re.match(r"supfirewall\s-r[ ]*$", command) != None : #commande pour avoir un resumé des regles appliqués
            with open("rules_table.txt", "r") as file:
                rules_table = json.loads(file.read())
                print("Active rules :")
                for rule,i in zip(rules_table['rules'],range(1,len(rules_table)+1)):
                    print("#{0} ip denied : {1}, port denied : {2} , protocol denied : {3}".format(i,rule["ip_source"],rule["port"],rule["protocol"]))

        elif re.match(r"supfirewall\s-h[ ]*$", command) != None : # commande affichage de l'aide pour utilisateur
            print("List of commands : \n"
                  "To create a new rule : \n"
                  "supfirewall -A -p x : blocked a x port \n"
                  "supfirewall -A -ips x.x.x.x : blocked a x.x.x.x ip address\n"
                  "supfirewall -A -Pt x : blocked a x protocol\n\n"
                  "You can combine args like this to create complete rule ! \n"
                  "supfirewall -A -p x -ips x.x.x.x \n"
                  "supfirewall -A -p x -Pt x \n"
                  "supfirewall -A -p x -ips x.x.x.x -Pt x\n"
                  "supfirewall -A -ips x.x.x.x -Pt x \n\n"
                  "To delete an existing rule , replace the -A argument by the -R argument ! \n"
                  "for example : supfirewall -R -ips x.x.x.x -Pt x \n\n"
                  "You can filter a pcap file with the rules table and get the output in filtered.pcap with :\n"
                  "supfirewall -f name_file.pcapng\n\n"
                  "You can have a summary of the active rules with :\n"
                  "supfirewall -r \n\n"
                  "You can quit the Supfirewall with : \n"
                  "supfirewall -q ")

        elif re.match(r"supfirewall\s-q[ ]*$", command) != None : #commande fermeture de l'application
            self.__isrunning = False
            print("\nSee you soon ;)")
            input("\nPress Enter to close the program ")

        else :
            print("'{0}' is not a command, type 'supfirewall -h' for help".format(command))

    def check_command(self,command):
        """Check si la command est une des commande permettant de crée une regle simple sur une ip, port ou protocole simple """

        return  re.match(r"supfirewall\s-[A,R]\s(-p\s" + regex['port'] + "|-Pt\s" + regex['protocol'] + "|-ips\s" + regex['ipv4'] + ")[ ]*$", command) != None or \
                re.match(r"supfirewall\s-[A,R]\s-p\s"+regex['port']+"\s(-Pt\s" + regex['protocol'] + "|-ips\s" + regex['ipv4'] + ")[ ]*$",command)!=None or \
                re.match(r"supfirewall\s-[A,R]\s-ips\s" + regex['ipv4'] + "\s-Pt\s" + regex['protocol'] + "[ ]*$", command) != None or \
                re.match(r"supfirewall\s-[A,R]\s-p\s"+regex['port']+"\s-ips\s" + regex['ipv4'] + "\s-Pt\s" + regex['protocol'] + "[ ]*$",command) != None


    def extract_data(self, command, target):
        """extraction des données : ip , protocole , port de la commande . Target => param passé dans la commande"""
        index = command.find(target)
        if index == -1:
            return '*'
        index += len(target) + 1
        data = ""
        while index != len(command) and command[index] != ' ':
            data += command[index]
            index += 1
        return data






