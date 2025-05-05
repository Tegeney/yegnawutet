from app import create_app, db
from models import User, TeacherPost, Grade, Subject, Score, Message

def clean_database():
    app = create_app()
    with app.app_context():
        try:
            # First check current message count
            current_messages = Message.query.all()
            print(f"\nCurrent messages in database: {len(current_messages)}")
            if current_messages:
                print("Message details:")
                for msg in current_messages:
                    print(f"- Message ID: {msg.id}, From: {msg.sender_id}, To: {msg.receiver_id}, Read: {msg.read}")
            
            print("\nStarting thorough database cleanup...")
            
            # Count existing records
            score_count = Score.query.count()
            message_count = Message.query.count()
            print(f"Found {score_count} scores and {message_count} messages")
            
            # Delete all scores and messages
            print("Deleting all scores and messages...")
            Message.query.delete()
            Score.query.delete()
            db.session.commit()
            
            # Verify deletion
            remaining_scores = Score.query.all()
            remaining_messages = Message.query.all()
            
            if remaining_scores:
                print("Warning: Some scores still remain. Forcing deletion...")
                for score in remaining_scores:
                    db.session.delete(score)
                
            if remaining_messages:
                print("Warning: Some messages still remain. Forcing deletion...")
                for message in remaining_messages:
                    db.session.delete(message)
            
            # Double check student 0099640
            student_640 = User.query.filter_by(username='0099640').first()
            if student_640:
                scores_640 = Score.query.filter_by(student_id=student_640.id).all()
                if scores_640:
                    print(f"Found {len(scores_640)} scores for student 0099640. Removing...")
                    for score in scores_640:
                        db.session.delete(score)
            
            # Final commit
            db.session.commit()
            
            # Final verification
            final_score_count = Score.query.count()
            final_message_count = Message.query.count()
            
            print("\nCleanup Results:")
            print(f"- Initial scores: {score_count} -> Final scores: {final_score_count}")
            print(f"- Initial messages: {message_count} -> Final messages: {final_message_count}")
            
            if final_score_count == 0 and final_message_count == 0:
                print("\nSuccess! Database is completely clean.")
            else:
                print("\nWarning: Some records may still remain.")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error during cleanup: {str(e)}")

if __name__ == '__main__':
    clean_database() 