from sys import argv
import pyautogui

def Main():
    if len(argv) < 3:
        print("Run: python ./mouse-click.py x y")

    pyautogui.click(x=int(argv[1]), y=int(argv[2]))

    print("Clicked at coordinate: (" + argv[1] + " , " + argv[2], ")")

if __name__ == '__main__':
    Main()