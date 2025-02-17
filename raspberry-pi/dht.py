import board
import adafruit_dht
import time
import digitalio  

dhtDevice = adafruit_dht.DHT22(board.D4) 

led = digitalio.DigitalInOut(board.D17)  
led.direction = digitalio.Direction.OUTPUT  

try:
    while True:
        temperature_c = dhtDevice.temperature
        humidity = dhtDevice.humidity
        
        if temperature_c is not None and humidity is not None:
            print(f'Temperature: {temperature_c:.2f}°C, Humidity: {humidity:.2f}%')

            if temperature_c > 20:
                led.value = True  
                time.sleep(0.5)   
                led.value = False  
                time.sleep(0.5)  

        else:
            print('Failed to retrieve data from the sensor.')

        time.sleep(2)  

except KeyboardInterrupt:
    print("Program stopped by user.")
finally:
    dhtDevice.exit()  