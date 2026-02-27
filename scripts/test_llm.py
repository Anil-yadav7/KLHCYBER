from backend.scoring.severity_engine import calculate_severity
from backend.remediation.llm_advisor import LLMAdvisor
from backend.database.connection import SessionLocal

def test_llm_pipeline():
    print('# Test severity engine')
    data_classes = ['Passwords', 'Email addresses', 'Phone numbers']
    result = calculate_severity(data_classes)
    print(f'Severity: {result.label} (score: {result.score})')
    print(f'Top risk: {result.top_risk}')
    print(f'Description: {result.description}')
    print()

    print('# Test LLM remediation (makes real Claude API call)')
    print('Calling Claude API for remediation steps...')
    db = SessionLocal()
    advisor = LLMAdvisor()
    try:
        remediation = advisor.generate_remediation(
            breach_name='LinkedIn',
            data_classes=data_classes,
            db_session=db
        )
        print('Remediation generated □')
        print('-' * 50)
        print(remediation[:600]) # Show first 600 chars
        print('-' * 50)
        print()
        print('Testing cache hit (second call should NOT call Claude)...')
        remediation2 = advisor.generate_remediation(
            breach_name='LinkedIn',
            data_classes=data_classes,
            db_session=db
        )
        print('Cache hit worked □' if remediation == remediation2 else 'Cache MISS Δ')
    except Exception as e:
        print(f'LLM test failed: {e}')
    finally:
        db.close()

if __name__ == '__main__':
    test_llm_pipeline()
