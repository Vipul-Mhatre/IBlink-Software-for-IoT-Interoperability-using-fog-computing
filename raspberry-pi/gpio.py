import RPi.GPIO as GPIO
import time

GPIO.setmode(GPIO.BCM)

DHT_PIN = 4   
LED_PIN = 17  

GPIO.setup(LED_PIN, GPIO.OUT)

def read_dht22():

    GPIO.setup(DHT_PIN, GPIO.OUT)
    GPIO.output(DHT_PIN, GPIO.LOW)
    time.sleep(0.02)  
    GPIO.output(DHT_PIN, GPIO.HIGH)
    time.sleep(0.00002)  
    GPIO.setup(DHT_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    count = 0
    while GPIO.input(DHT_PIN) == GPIO.LOW:
        count += 1
        if count > 100:  
            return None, None

    data = []
    for i in range(40):  
        count = 0
        while GPIO.input(DHT_PIN) == GPIO.HIGH:
            count += 1
            if count > 100: 
                return None, None

        data.append(count)

    humidity_bits = sum((1 << (39 - i) for i in range(0, 16) if data[i] > 5))
    temperature_bits = sum((1 << (39 - i) for i in range(16, 32) if data[i] > 5))
    
    humidity = humidity_bits / 10.0
    temperature = temperature_bits / 10.0

    return humidity, temperature

try:
    while True:
        humidity, temperature = read_dht22()
        
        if humidity is not None and temperature is not None:
            print(f'Temperature: {temperature:.1f}°C, Humidity: {humidity:.1f}%')

            if temperature > 25:
                GPIO.output(LED_PIN, GPIO.HIGH) 
            else:
                GPIO.output(LED_PIN, GPIO.LOW)  
        else:
            print('Failed to get reading. Try again!')
        time.sleep(2)

except KeyboardInterrupt:
    print("Program stopped by User")
finally:
    GPIO.cleanup() 