with open('text.txt', 'rb') as file:
    while True:
        data = file.read(4)
        if not data:
            break
        print(data)