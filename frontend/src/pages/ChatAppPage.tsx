import Logout from "@/components/auth/Logout";
import { useAuthStore } from "@/stores/useAuthStore";

const ChatAppPage = () => {
  const { fetchMe } = useAuthStore();
  const user = useAuthStore((s) => s.user);

  return (
    <div>
      {user?.username}
      <Logout />
      <button
        onClick={() => {
          fetchMe();
        }}
      >
        Refresh me
      </button>
    </div>
  );
};

export default ChatAppPage;
