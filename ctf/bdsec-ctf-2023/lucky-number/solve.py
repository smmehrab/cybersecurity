def luckyNumberGen():
    var_28h = 0
    var_20h = 1
    result = 0
    
    for _ in range(50):
        result += var_28h
        var_28h, var_20h = var_20h, var_20h + var_28h
    
    return result

# reverse of this number = lucky number
print(luckyNumberGen())