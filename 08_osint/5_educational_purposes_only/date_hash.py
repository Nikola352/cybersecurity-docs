import hashlib
from datetime import datetime, timedelta
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count

def check_date(date_tuple):
    """Check a single date (used by parallel workers)"""
    year, month, day = date_tuple
    date_str = f"{day:02d}/{month:02d}/{year}"
    md5_hash = hashlib.md5(date_str.encode()).hexdigest()
    return (date_str, md5_hash)

def find_date_parallel(target_hash):
    """Parallel version using all CPU cores"""
    start_date = datetime(2000, 1, 1)
    end_date = datetime(2013, 12, 31)
    
    # Generate all dates
    dates = []
    current = start_date
    while current <= end_date:
        dates.append((current.year, current.month, current.day))
        current += timedelta(days=1)
    
    print(f"Checking {len(dates)} dates using {cpu_count()} cores...")
    
    # Process in parallel
    with ProcessPoolExecutor(max_workers=cpu_count()) as executor:
        futures = {executor.submit(check_date, date): date for date in dates}
        
        for i, future in enumerate(as_completed(futures), 1):
            date_str, md5_hash = future.result()
            
            if md5_hash == target_hash:
                # Cancel remaining futures
                for f in futures:
                    f.cancel()
                print(f"\n✓ Found match!")
                print(f"  Date: {date_str}")
                print(f"  MD5:  {md5_hash}")
                return date_str
    
    print(f"\n✗ No matching date found for hash: {target_hash}")
    return None

if __name__ == "__main__":
    target = "f4d7caf81e33bc156cc3e98cf8095d2e"
    
    print("=" * 50)
    print("MD5 Date Finder")
    print("=" * 50)
    print(f"Target MD5: {target}")
    print("-" * 50)
    
    result = find_date_parallel(target)
