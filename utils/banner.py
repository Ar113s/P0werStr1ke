from colorama import Fore, Style

def show():

    banner = f"""
{Fore.CYAN}    ╔───────────────────────────────────────────────────────────────────────────────────────╗
{Fore.BLUE}    │                                                                                       │
{Fore.LIGHTBLUE_EX}    │   88""Yb  dP"Yb  Yb        dP 888888 88""Yb .dP"Y8 888888 88""Yb   .d 88  dP 888888   │
{Fore.BLUE}    │   88__dP dP   Yb  Yb  db  dP  88__   88__dP `Ybo."   88   88__dP .d88 88odP  88__     │
{Fore.LIGHTCYAN_EX}    │   88 """ + f'{Fore.WHITE}""' + f"""{Fore.LIGHTCYAN_EX}  Yb   dP   YbdPYbdP   88""   88"Yb  o.`Y8b   88   88"Yb    88 88"Yb  88""     │
{Fore.LIGHTBLUE_EX}    │   88      YbodP     YP  YP    888888 88  Yb 8bodP'   88   88  Yb   88 88  Yb 888888   │
{Fore.BLUE}    │                                                                                       │
{Fore.CYAN}    ╚───────────────────────────────────────────────────────────────────────────────────────╝{Style.RESET_ALL}
    
{Fore.LIGHTBLUE_EX}                        [ {Fore.WHITE}Advanced PowerShell Penetration Framework{Fore.LIGHTBLUE_EX} ]
{Fore.BLUE}                               [ {Fore.CYAN}Professional Security Toolkit{Fore.BLUE} ]{Style.RESET_ALL}
    """

    return banner

if __name__ == "__main__":

    print(show())