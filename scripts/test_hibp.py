from backend.ingestion.hibp_client import HIBPClient

def test_hibp():
    with HIBPClient() as client:
        print('Testing HIBP API connection...')

        # This email is known to be in many public breaches
        try:
            breaches = client.get_breaches_for_email('test@example.com')

            if breaches:
                print(f'Found {len(breaches)} breach(es) - API working □')
                first = client.normalize_breach(breaches[0])
                print(f'First breach: {first["name"]}')
                print(f'Data classes: {first["data_classes"][:3]}...')
                print(f'Breach date:  {first["breach_date"]}')
            elif breaches == []:
                print('No breaches found (404) - API connected but email clean □')
        except Exception as e:
            print(f'Unexpected response - check API key ({e})')

        print('\nTesting password pwned check (k-anonymity)...')
        # 'password' is the world's most common password - definitely pwned
        count = client.check_password_pwned('password')
        if count > 0:
            print(f'password pwned {count:,} times □')
        else:
            print('Not found (unexpected)')

        # Test with a random secure password - should return 0
        count2 = client.check_password_pwned('Xq8#mK2@pL9$wR5!vB')
        if count2 == 0:
            print(f'Random secure password: pwned {count2} times (expected 0) □')
        else:
            print(f'Found {count2} times')

if __name__ == '__main__':
    test_hibp()
