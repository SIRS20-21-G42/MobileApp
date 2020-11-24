package com.example.sirsapp.ui.Authorization;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.example.sirsapp.R;

import java.util.List;

public class AuthorizationAdapter extends RecyclerView.Adapter<AuthorizationAdapter.AuthorizationViewHolder> {

    // manages the view holder objects

    private Context context;
    private List<AuthorizationItem> list;
    private OnItemClickListener listener;

    public interface OnItemClickListener {
        void onItemClick(int position);
        void onItemAccept(int position);
        void onItemDeny(int position);
    }

    public static class AuthorizationViewHolder extends RecyclerView.ViewHolder{
        // Displays a single item with the view

        TextView authorizationHash;
        Button acceptButton;
        Button declineButton;

        public AuthorizationViewHolder(@NonNull View itemView, OnItemClickListener mListener) {
            super(itemView);
            this.authorizationHash = itemView.findViewById(R.id.authorizationTextView);
            this.acceptButton = itemView.findViewById(R.id.acceptAuthorizationButton);
            this.declineButton = itemView.findViewById(R.id.declineAuthorizationButton);

            setupClickListeners(mListener);
        }

        private void setupClickListeners(OnItemClickListener mListener){
            authorizationHash.setOnClickListener(v -> {
                if (mListener != null){
                    int position = getAdapterPosition();
                    if (position != RecyclerView.NO_POSITION){
                        mListener.onItemClick(position);
                    }
                }
            });

            acceptButton.setOnClickListener(v -> {
                if (mListener != null){
                    int position = getAdapterPosition();
                    if (position != RecyclerView.NO_POSITION){
                        mListener.onItemAccept(position);
                    }
                }
            });

            declineButton.setOnClickListener(v -> {
                if (mListener != null){
                    int position = getAdapterPosition();
                    if (position != RecyclerView.NO_POSITION){
                        mListener.onItemDeny(position);
                    }
                }
            });
        }
    }

    public void setOnItemClickListener(OnItemClickListener itemListener){
        this.listener = itemListener;
    }

    public AuthorizationAdapter(Context context, List<AuthorizationItem> list) {
        this.list = list;
        this.context = context;
    }

    @NonNull
    @Override
    public AuthorizationViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        // create each object of the view

        LayoutInflater inflater = LayoutInflater.from(this.context);

        View view = (View) inflater.inflate(R.layout.authorization_element_layout, parent, false);

        AuthorizationViewHolder authorizationViewHolder = new AuthorizationViewHolder(view, this.listener);

        return authorizationViewHolder;
    }

    @Override
    public void onBindViewHolder(@NonNull AuthorizationViewHolder holder, int position) {
        // assign data to view components
        if (list.get(position).getHash().length() > 5) {
            String text = list.get(position).getHash().substring(0, 5) + "...";
            holder.authorizationHash.setText(text);
        } else {
            holder.authorizationHash.setText(list.get(position).getHash());
        }
    }

    @Override
    public int getItemCount() {
        return list.size();
    }

}
