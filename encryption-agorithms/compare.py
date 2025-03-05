import subprocess
import sys
import os
import traceback
import re

def run_script(script_path):
    try:
        result = subprocess.run(
            [sys.executable, script_path], 
            capture_output=True, 
            text=True, 
            timeout=300,
            check=True
        )
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running {os.path.basename(script_path)}:")
        print("STDOUT:", e.stdout)
        print("STDERR:", e.stderr)
        traceback.print_exc()
        return e.stdout, e.stderr
    except Exception as e:
        print(f"Unexpected error running {os.path.basename(script_path)}:")
        traceback.print_exc()
        return "", str(e)

def parse_performance_output(output):
    performance_data = {
        'encryption_time': 0,
        'decryption_time': 0,
        'total_time': 0
    }
    
    try:
        encryption_match = re.search(r'Encryption Time: ([\d.]+)', output)
        decryption_match = re.search(r'Decryption Time: ([\d.]+)', output)
        total_match = re.search(r'Total Time: ([\d.]+)', output)
        
        if encryption_match:
            performance_data['encryption_time'] = float(encryption_match.group(1))
        if decryption_match:
            performance_data['decryption_time'] = float(decryption_match.group(1))
        if total_match:
            performance_data['total_time'] = float(total_match.group(1))
    except Exception as e:
        print(f"Error parsing performance output: {e}")
    
    return performance_data

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    encryption_scripts = [
        'iblink.py',
        'rsa.py',
        'aes.py',
        'blowfish.py',
        # 'ecc.py'
    ]

    results = {}
    
    print("Encryption Algorithm Performance Comparison: ")
    print("For bigger message: Hello Vipul Mhatre")
    for script in encryption_scripts:
        script_path = os.path.join(script_dir, script)
        print(f"\n{script}:")
        
        output, error = run_script(script_path)
        print(output)
        
        if error:
            print(f"Error output for {script}:")
            print(error)
        
        performance = parse_performance_output(output)
        results[script] = performance

    # # Comparative Analysis
    # print("\nComparative Analysis:")
    
    # fastest_script = min(results, key=lambda x: results[x]['total_time'])
    
    # print(f"Fastest Algorithm: {fastest_script}")
    # print(f"Total Processing Time: {results[fastest_script]['total_time']:.6f} sec")
    
    # # Detailed Comparison
    # print("\nPerformance Metrics Comparison:")
    # for script, perf in results.items():
    #     print(f"\n{script}:")
    #     print(f"  Encryption Time: {perf['encryption_time']:.6f} sec")
    #     print(f"  Decryption Time: {perf['decryption_time']:.6f} sec")
    #     print(f"  Total Time: {perf['total_time']:.6f} sec")

if __name__ == "__main__":
    main()
